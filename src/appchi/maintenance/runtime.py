"""Bridge for suppression replay and durable original-time derived effects.

Correlation must merge maintenance_effect_outbox with its ordinary journal by
tenant change_order, retract withdrawals and recheck current authoritative state.
That consumer is deliberately not claimed by this module.
"""

from time import monotonic
from uuid import UUID, uuid5

from psycopg.types.json import Jsonb

from appchi.alerts.lifecycle import SEMANTIC_FIELDS
from appchi.cel.catalog import RULE_FIELDS
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import wire

from .processing import (
    claim_due,
    finish_failed_job,
    prepare_catalog,
    record_input,
    record_transition,
    reconcile_alert,
    step_job,
)
from .temporal import MaintenanceProofError


def prepare_for_tenant(database, tenant, profile):
    with database.transaction(tenant) as conn:
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='maintenance'"
        ).fetchone()
    if not gate or not gate["ready"]:
        return None
    return prepare_qualified_catalog(database, tenant, profile)


def prepare_qualified_catalog(database, tenant, profile):
    """Compile with a qualified budget, including offline proof warmup."""
    names = ("maintenance_max_work", "maintenance_max_inputs", "maintenance_max_segments")
    if (
        not isinstance(profile, dict)
        or profile.get("qualified") is not True
        or any(type(profile.get(name)) is not int or profile[name] < 1 for name in names)
    ):
        raise unavailable("maintenance_capacity_profile_required")
    return prepare_catalog(
        database,
        tenant,
        max_work=profile[names[0]],
        max_inputs=profile[names[1]],
        max_segments=profile[names[2]],
    )


def lock_catalog(conn, catalog):
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
    lock_contexts(conn, tenant)


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
    gate = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='maintenance'"
    ).fetchone()
    if bool(gate and gate["ready"]) != (catalog is not None):
        raise unavailable("maintenance_gate_changed")
    needs_input = (
        cause == "source"
        or before is None
        or any(before[field] != after[field] for field in RULE_FIELDS)
    )
    if catalog is None:
        if conn.execute(
            "SELECT 1 FROM maintenance_segments WHERE tenant_id=%s LIMIT 1", (after["tenant_id"],)
        ).fetchone():
            raise unavailable("maintenance_gate_closed_with_timeline")
        if needs_input:
            record_input(conn, before, after, when, order, cause, now)
        adjusted, effects = dict(after), None
    elif needs_input:
        adjusted, effects = record_transition(
            conn, before, after, when, order, cause, now, catalog=catalog
        )
    else:
        adjusted, effects = reconcile_alert(conn, after, now, catalog=catalog)
    changed = (
        before is None
        or any(before[field] != adjusted[field] for field in SEMANTIC_FIELDS)
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
        """SELECT after_snapshot FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s
        AND (effective_at<%s OR (effective_at=%s AND original_order<=%s)) ORDER BY effective_at DESC,original_order DESC LIMIT 1""",
        (tenant, alert_id, at, at, order),
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


def worker_turn(database, tenant, profile):
    """One bounded fan-out turn; shared host schedules calls once per second.

    Publication uses correlation contexts, linked incidents and source fences.
    """
    catalog = prepare_for_tenant(database, tenant, profile)
    if catalog is None:
        return 0
    lease = claim_due(database, tenant)
    if lease is None:
        return 0
    catalog = prepare_for_tenant(database, tenant, profile)
    if catalog is None:
        finish_failed_job(database, lease, proof_blocked=False)
        return 0
    from appchi.alerts.routes import pending, retained
    from appchi.incidents.routes import lock_linked_incidents

    def lock(conn, tenant_id, alert_id):
        if not conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='maintenance'"
        ).fetchone()["ready"]:
            raise unavailable("maintenance_gate_changed")
        from appchi.correlation.runtime import lock_contexts

        lock_contexts(conn, tenant_id)
        lock_linked_incidents(conn, tenant_id, alert_id)
        row = retained(conn, tenant_id, alert_id, True)
        pending(conn, tenant_id, row)
        return row

    started, processed = monotonic(), 0
    try:
        while processed < 100 and monotonic() - started < 0.1:
            state = step_job(
                database, lease, catalog, lock_alert=lock, publish=publish_reconciliation
            )
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
