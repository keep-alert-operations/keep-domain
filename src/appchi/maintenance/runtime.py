"""Suppression proof and atomic original-time correlation release effects."""

from dataclasses import dataclass, replace
from datetime import datetime
from time import monotonic
from uuid import UUID, uuid5

from psycopg.types.json import Jsonb

from appchi.alerts.dismissal import correlation_suppressed
from appchi.alerts.lifecycle import SEMANTIC_FIELDS
from appchi.cel.catalog import RULE_FIELDS
from appchi.shared.capacity import budget
from appchi.shared.errors import AppError, unavailable
from appchi.serialization import wire

from .processing import (
    claim_due,
    compile_catalog,
    finish_failed_job,
    prepare_catalog,
    read_catalog,
    record_transition,
    reconcile_alert,
    step_job,
)
from .temporal import MaintenanceProofError


@dataclass(frozen=True)
class InlineCorrelation:
    database: object
    profile: dict
    prepared: object


def prepare_for_tenant(
    database,
    tenant,
    profile,
    *,
    inline=True,
    alert_id=None,
    effective_at=None,
    source_item=None,
    alert_ids=(),
):
    # One snapshot supplies the catalog and the target checkpoints.
    snapshot = read_catalog(
        database, tenant, alert_id=alert_id, effective_at=effective_at, alert_ids=alert_ids
    )
    catalog = compile_catalog(snapshot, **_budget(profile))
    targets, at = snapshot.targets, snapshot.at
    if targets:
        from .preparation import prepare_replay

        replays = {}
        for target in targets:
            continuation = snapshot.continuations.get(target)
            needs_replay = (
                not continuation
                or continuation.get("version") not in (1, "1", 2, "2")
                or int(continuation["generation"]) != catalog.generation
                or continuation.get("source_release_since") != wire(catalog.source_release_since)
                or catalog.source_release_since is None
                or at < catalog.source_release_since
                or at <= datetime.fromisoformat(continuation.get("max_at", continuation["last_at"]))
            )
            if needs_replay:
                if not catalog.history_complete:
                    catalog = prepare_full_catalog(database, tenant, profile)
                replay = prepare_replay(database, catalog, target, source_item=source_item)
                if replay is not None:
                    replays[UUID(target)] = replay
        catalog = replace(catalog, replays=replays)
    catalog = replace(catalog, require_preparation=True)
    if inline:
        catalog = replace(catalog, inline_requested=True)
        # lock_catalog and worker_turn recheck this observation under locks.
        if snapshot.correlation_enabled:
            from appchi.correlation.runtime import prepare_tenant

            prepared = prepare_tenant(
                database, tenant, profile, maintenance_input=catalog, alert_ids=targets
            )
            catalog = replace(
                prepared.maintenance,
                inline_correlation=InlineCorrelation(database, profile, prepared),
            )
    return catalog


def prepare_full_catalog(database, tenant, profile, *, alert_id=None, effective_at=None, alert_ids=()):
    """Compile the whole catalog within the configured budget, including proof warmup."""
    return prepare_catalog(
        database,
        tenant,
        **_budget(profile),
        alert_id=alert_id,
        effective_at=effective_at,
        alert_ids=alert_ids,
    )


def _budget(profile):
    """Configured maintenance work budgets; each unset budget is unlimited (REV-39)."""
    profile = profile if isinstance(profile, dict) else None
    return {
        "max_work": budget(profile, "maintenance_max_work"),
        "max_inputs": budget(profile, "maintenance_max_inputs"),
        "max_segments": budget(profile, "maintenance_max_segments"),
    }


def lock_catalog(conn, catalog, *, targets=(), incidents=()):
    """Call after coordinator and before any incident/alert locks."""
    if catalog:
        conn.execute(
            "SELECT id FROM maintenance_windows WHERE tenant_id=%s AND id=ANY(%s::uuid[]) ORDER BY id FOR UPDATE",
            (catalog.tenant_id, sorted({str(segment.window_id) for segment in catalog.segments})),
        ).fetchall()
    from appchi.correlation.runtime import lock_contexts

    tenant = (
        catalog.tenant_id
        if catalog
        else conn.execute("SELECT current_setting('appchi.tenant_id',true) AS tenant").fetchone()[
            "tenant"
        ]
    )
    if not tenant:
        raise unavailable("maintenance_tenant_scope_required")
    lock_contexts(
        conn,
        tenant,
        targets=targets,
        incidents=incidents,
        live=bool(catalog and catalog.inline_correlation),
    )
    if (
        catalog
        and catalog.inline_requested
        and catalog.inline_correlation is None
        and conn.execute(
            """SELECT 1 FROM correlation_rules WHERE tenant_id=%s AND enabled
            AND NOT kafka_schema_blocked AND deleted_at IS NULL LIMIT 1""",
            (tenant,),
        ).fetchone()
    ):
        raise unavailable("correlation_compiled_revision_changed")
    # Bind to the transaction, because the pooled connection outlives it.
    transaction = conn.execute("SELECT pg_current_xact_id()::text AS id").fetchone()["id"]
    conn._appchi_inline_maintenance = (transaction, catalog.inline_correlation if catalog else None)
    if getattr(conn, "_appchi_inline_transaction", None) != transaction:
        conn._appchi_inline_transaction = transaction
        conn._appchi_inline_alerts = set()
    if catalog and catalog.inline_correlation:
        from appchi.correlation.runtime import lock_decision_scope

        # lock_contexts above already ran with live=True and these targets.
        lock_decision_scope(conn, tenant, targets, incidents=incidents, contexts_locked=True)


def apply_transition(conn, before, after, when, order, cause, now, catalog):
    try:
        return _apply_transition(conn, before, after, when, order, cause, now, catalog)
    except MaintenanceProofError:
        raise unavailable("maintenance_proof_unavailable") from None


def _apply_transition(conn, before, after, when, order, cause, now, catalog):
    """Return adjusted state, semantic-change flag, and Effects or None.

    Caller owns coordinator/aggregate/alert locks and has inserted new identity.
    Recompute revisions from actual content, undoing apply_source's temporary
    source-only suppression comparison. Every source increments projection once.
    """
    if catalog is None:
        raise unavailable("maintenance_catalog_required")
    needs_input = (
        cause == "source"
        or before is None
        or any(before[field] != after[field] for field in RULE_FIELDS)
    )
    if needs_input:
        adjusted, effects = record_transition(
            conn, before, after, when, order, cause, now, catalog=catalog
        )
    else:
        adjusted, effects = reconcile_alert(conn, after, now, catalog=catalog)
    changed = (
        before is None
        or any(before.get(field) != adjusted.get(field) for field in SEMANTIC_FIELDS)
        or (cause != "source" and after["revision"] > before["revision"])
    )
    if before is None:
        adjusted["revision"] = 1
        adjusted["projection_version"] = 1
    else:
        adjusted["revision"] = before["revision"] + int(changed)
        adjusted["projection_version"] = before["projection_version"] + int(
            changed or cause == "source" or bool(effects and effects.history_changed)
        )
    if effects:
        persist_effects(conn, adjusted, effects, now)
    return adjusted, changed, effects


def _qualifier_proof(conn, tenant, alert_id, at):
    boundary = conn.execute(
        """SELECT * FROM maintenance_cause_history WHERE tenant_id=%s AND alert_id=%s AND boundary_kind='close' AND effective_at=%s
        ORDER BY (evidence->>'order')::bigint DESC,id DESC LIMIT 1""",
        (tenant, alert_id, at),
    ).fetchone()
    if not boundary:
        raise MaintenanceProofError("maintenance_qualifier_boundary_missing")
    order = int(boundary["evidence"]["order"])
    snapshot = conn.execute(
        """SELECT i.after_snapshot FROM maintenance_qualifier_effects q JOIN maintenance_alert_inputs i
        ON i.tenant_id=q.tenant_id AND i.alert_id=q.alert_id AND i.id=q.source_input_id
        WHERE q.tenant_id=%s AND q.alert_id=%s AND q.effective_at=%s AND q.active LIMIT 1""",
        (tenant, alert_id, at),
    ).fetchone()
    if not snapshot or snapshot["after_snapshot"]["status"] != "firing":
        raise MaintenanceProofError("maintenance_qualifier_snapshot_missing")
    return (
        boundary["boundary_id"],
        order,
        boundary["boundary_id"].startswith("end:"),
        snapshot["after_snapshot"],
    )


def persist_effects(conn, current, effects, now):
    """Append qualifier/correction proof; never manufacture a source input."""
    tenant, alert_id = current["tenant_id"], UUID(str(current["id"]))
    actions = [(identity, "activate", at) for identity, at in effects.qualifiers]
    actions.extend((identity, "withdraw", None) for identity in effects.withdrawn_qualifiers)
    if correlation_suppressed(current):
        conn.execute(
            "DELETE FROM correlation_evidence WHERE tenant_id=%s AND alert_id=%s",
            (tenant, alert_id),
        )
    for qualifier in effects.withdrawn_qualifiers:
        conn.execute(
            "DELETE FROM correlation_evidence WHERE tenant_id=%s AND alert_id=%s AND qualifier_ref=%s",
            (tenant, alert_id, qualifier),
        )
    for qualifier, action, at in actions:
        event_id = uuid5(qualifier, action + ":" + effects.proof_digest.hex())
        if conn.execute(
            "SELECT 1 FROM maintenance_effect_outbox WHERE tenant_id=%s AND id=%s",
            (tenant, event_id),
        ).fetchone():
            continue
        previous = conn.execute(
            "SELECT * FROM maintenance_effect_outbox WHERE tenant_id=%s AND alert_id=%s AND qualifier_id=%s ORDER BY change_order DESC LIMIT 1",
            (tenant, alert_id, qualifier),
        ).fetchone()
        conn.execute(
            "UPDATE maintenance_effect_outbox SET processed_at=%s WHERE tenant_id=%s AND alert_id=%s AND qualifier_id=%s AND processed_at IS NULL",
            (now, tenant, alert_id, qualifier),
        )
        if action == "activate":
            boundary, order, scheduled, snapshot = _qualifier_proof(conn, tenant, alert_id, at)
            before, after = dict(snapshot, suppressed=True), dict(snapshot, suppressed=False)
        else:
            if not previous:
                raise MaintenanceProofError("maintenance_withdrawal_reference_missing")
            at, boundary, order, scheduled = (
                previous["effective_at"],
                previous["boundary_id"],
                previous["original_order"],
                previous["scheduled"],
            )
            before, after = previous["before_snapshot"], previous["after_snapshot"]
        change = conn.execute(
            "UPDATE tenant_work_state SET change_order=change_order+1 WHERE tenant_id=%s RETURNING change_order",
            (tenant,),
        ).fetchone()["change_order"]
        conn.execute(
            """INSERT INTO maintenance_effect_outbox(tenant_id,alert_id,id,qualifier_id,change_order,action,effective_at,original_order,scheduled,boundary_id,before_snapshot,after_snapshot,observed_revision,proof_digest,corrects_id,recorded_at)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                tenant,
                alert_id,
                event_id,
                qualifier,
                change,
                action,
                at,
                order,
                scheduled,
                boundary,
                Jsonb(before),
                Jsonb(after),
                current["revision"],
                effects.proof_digest,
                previous["id"] if previous else None,
                now,
            ),
        )
        conn.execute(
            """INSERT INTO alert_activity(tenant_id,alert_id,id,change_order,recorded_at,effective_at,kind,evidence)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                tenant,
                alert_id,
                event_id,
                change,
                now,
                at,
                "maintenance-qualifier-" + action,
                Jsonb(
                    wire(
                        {
                            "qualifier_id": qualifier,
                            "effect_id": event_id,
                            "corrects_id": previous["id"] if previous else None,
                            "boundary_id": boundary,
                            "original_order": order,
                            "scheduled": scheduled,
                        }
                    )
                ),
            ),
        )


def publish_reconciliation(conn, before, after, effects, now):
    """Publish derived materialization without inventing a qualifier input."""
    from appchi.alerts.repository import publish, store_alert

    after["revision"] = before["revision"] + int(effects.suppression_changed)
    after["projection_version"] = before["projection_version"] + int(
        effects.suppression_changed or effects.history_changed
    )
    persist_effects(conn, after, effects, now)
    if effects.suppression_changed or effects.history_changed:
        store_alert(conn, after)
        publish(
            conn,
            before,
            after,
            now,
            "maintenance-materialization",
            semantic=effects.suppression_changed,
        )
    publish_inline_effects(conn, after)


def publish_inline_effects(conn, current):
    """Register a target for the transaction's pre-commit release evaluation."""
    binding = getattr(conn, "_appchi_inline_maintenance", None)
    if not binding or binding[1] is None or getattr(conn, "_appchi_inline_running", False):
        return
    if str(binding[1].prepared.tenant) != str(current["tenant_id"]):
        return
    if binding[0] == conn.execute("SELECT pg_current_xact_id()::text AS id").fetchone()["id"]:
        conn._appchi_inline_alerts.add(UUID(str(current["id"])))


def flush_inline_effects(conn):
    """Finish manual/source/fan-out mutations before deriving incident effects.

    This executes before commit, so bulk operations cannot overwrite a revision
    changed by an inline decision midway through their previously loaded rows.
    """
    binding = getattr(conn, "_appchi_inline_maintenance", None)
    if not binding or binding[1] is None or not getattr(conn, "_appchi_inline_alerts", None):
        return
    if binding[0] != conn.execute("SELECT pg_current_xact_id()::text AS id").fetchone()["id"]:
        return
    for identity in sorted(conn._appchi_inline_alerts):
        current = conn.execute(
            "SELECT * FROM alerts WHERE tenant_id=%s AND id=%s",
            (binding[1].prepared.tenant, identity),
        ).fetchone()
        if current:
            _apply_inline_effects(conn, current)
    conn._appchi_inline_alerts.clear()


def _apply_inline_effects(conn, current):
    """Apply release proof after current state and manual boundaries are stored.

    Proof awaiting a source's Kafka turn remains available to that turn. Nested
    incident publications cannot re-enter the same inline decision loop.
    """
    binding = getattr(conn, "_appchi_inline_maintenance", None)
    if not binding or binding[1] is None or getattr(conn, "_appchi_inline_running", False):
        return
    transaction, scope = binding
    if str(scope.prepared.tenant) != str(current["tenant_id"]):
        return
    if transaction != conn.execute("SELECT pg_current_xact_id()::text AS id").fetchone()["id"]:
        return
    from appchi.correlation.runtime import maintenance_input, worker_turn as correlation_turn

    effects = conn.execute(
        """SELECT * FROM maintenance_effect_outbox WHERE tenant_id=%s AND alert_id=%s
        AND processed_at IS NULL ORDER BY change_order""",
        (current["tenant_id"], current["id"]),
    ).fetchall()
    conn._appchi_inline_running = True
    try:
        for effect in effects:
            if effect["action"] == "activate" and scope.prepared.rows:
                alert = conn.execute(
                    "SELECT * FROM alerts WHERE tenant_id=%s AND id=%s",
                    (current["tenant_id"], current["id"]),
                ).fetchone()
                owner = conn.execute(
                    "SELECT incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
                    (current["tenant_id"], current["id"]),
                ).fetchone()
                if not maintenance_input(
                    conn, effect, alert, owner["incident_id"] if owner else None, 1
                ):
                    continue
                correlation_turn(
                    scope.database,
                    current["tenant_id"],
                    scope.profile,
                    prepared_input=scope.prepared,
                    transaction=conn,
                    kafka=True,
                    input_event=dict(effect, stream="effect"),
                )
                while (
                    state := conn.execute(
                        "SELECT pending FROM correlation_consumer_state WHERE tenant_id=%s",
                        (current["tenant_id"],),
                    ).fetchone()
                ) and state["pending"]:
                    if not correlation_turn(
                        scope.database,
                        current["tenant_id"],
                        scope.profile,
                        prepared_input=scope.prepared,
                        transaction=conn,
                        kafka=True,
                    ):
                        break
            conn.execute(
                "UPDATE maintenance_effect_outbox SET processed_at=clock_timestamp() WHERE tenant_id=%s AND id=%s",
                (current["tenant_id"], effect["id"]),
            )
    finally:
        conn._appchi_inline_running = False


def worker_turn(database, tenant, profile):
    """One bounded fan-out turn; shared host schedules calls once per second.

    Publication uses correlation contexts, linked incidents and source fences.
    """
    prepare_for_tenant(database, tenant, profile)
    lease = claim_due(database, tenant)
    if lease is None:
        return 0
    catalog = prepare_for_tenant(database, tenant, profile)
    from appchi.alerts.state import pending, retained
    from appchi.incidents.state import lock_linked_incidents

    def lock(conn, tenant_id, alert_id):
        lock_catalog(conn, catalog, targets=[alert_id])
        if not catalog.inline_correlation:
            lock_linked_incidents(conn, tenant_id, alert_id)
        row = retained(conn, tenant_id, alert_id, True)
        pending(conn, tenant_id, row)
        return row

    def publish_inline(conn, before, after, effects, now):
        publish_reconciliation(conn, before, after, effects, now)

    started, processed = monotonic(), 0
    try:
        while processed < 100 and monotonic() - started < 0.1:
            state = step_job(database, lease, catalog, lock_alert=lock, publish=publish_inline)
            if state != "processed":
                return processed
            processed += 1
    except MaintenanceProofError:
        finish_failed_job(database, lease, proof_blocked=True)
        raise
    except AppError:
        finish_failed_job(database, lease, proof_blocked=False)
        raise
    # Release fairly so the next one-second scan can continue with a new fence.
    finish_failed_job(database, lease, proof_blocked=False)
    return processed
