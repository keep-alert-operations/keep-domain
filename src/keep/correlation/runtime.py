"""PostgreSQL correlation consumer and incident context boundaries.

Compilation happens before coordinator acquisition. A turn applies one input
to every configured rule and commits at most one complete winning incident.
"""

from dataclasses import dataclass, replace
from contextlib import nullcontext
from datetime import datetime
import json
from uuid import UUID, uuid4, uuid5

from psycopg.types.json import Jsonb

from keep.alerts.dismissal import correlation_suppressed, dismissal_recorded
from keep.cel.catalog import CORRELATION_FIELDS as RULE_FIELDS, alert_name
from keep.shared.errors import AppError, unavailable
from keep.shared.transactions import coordinator
from keep.serialization import wire
from . import repository as repo
from .evidence import (
    Boundary,
    Budgets,
    Context,
    CorrelationProofError,
    EvidenceState,
    GroupKey,
    Input,
    Membership,
    ReplayTransition,
    Snapshot,
    apply_all,
    choose_decision,
    replay_alert,
    group_key,
)


def lock_contexts(conn, tenant, *, targets=None, incidents=(), live=True):
    """Lock live decision contexts after the tenant coordinator.

    Dormant historical groups cannot participate in arbitration. Their reset
    proof is still read by exact group when needed; the coordinator excludes
    concurrent tenant mutations while a dormant group becomes relevant again.
    """
    conn.execute(
        "SELECT id FROM correlation_rules WHERE tenant_id=%s AND enabled AND deleted_at IS NULL ORDER BY id FOR UPDATE",
        (tenant,),
    ).fetchall()
    conn.execute(
        """WITH relevant AS (
          SELECT id FROM correlation_contexts WHERE tenant_id=%s AND %s AND active_incident_id IS NOT NULL
          UNION SELECT e.context_id FROM correlation_evidence e JOIN correlation_rules r
            ON r.tenant_id=e.tenant_id AND r.id=e.rule_id AND r.epoch=e.epoch
            WHERE e.tenant_id=%s AND %s AND e.expires_at>clock_timestamp()
          UNION SELECT context_id FROM incidents WHERE tenant_id=%s AND id=ANY(%s::uuid[])
          UNION SELECT i.context_id FROM incident_alert_links l JOIN incidents i
            ON i.tenant_id=l.tenant_id AND i.id=l.incident_id
            WHERE l.tenant_id=%s AND l.alert_id=ANY(%s::uuid[]) AND l.unlinked_at IS NULL)
        SELECT c.id FROM relevant r JOIN correlation_contexts c ON c.id=r.id
        WHERE c.tenant_id=%s ORDER BY c.rule_id,c.grouping_generation,c.group_key,c.id FOR UPDATE OF c""",
        (
            tenant,
            targets is None,
            tenant,
            live,
            tenant,
            list(incidents),
            tenant,
            list(targets or ()),
            tenant,
        ),
    ).fetchall()


def release_alert(conn, tenant, alert_id, now):
    order = conn.execute(
        "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
        (tenant,),
    ).fetchone()["admission_order"]
    conn.execute(
        "INSERT INTO correlation_boundaries(tenant_id,alert_id,order_token,effective_at) VALUES(%s,%s,%s,%s) ON CONFLICT(tenant_id,alert_id) DO UPDATE SET order_token=EXCLUDED.order_token,effective_at=EXCLUDED.effective_at",
        (tenant, alert_id, order, now),
    )
    conn.execute(
        "DELETE FROM correlation_evidence WHERE tenant_id=%s AND alert_id=%s", (tenant, alert_id)
    )


def resolve_context(conn, incident, now):
    if incident["context_id"] is None:
        return
    order = conn.execute(
        "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
        (incident["tenant_id"],),
    ).fetchone()["admission_order"]
    # Target the exact retained context, including an older grouping generation.
    conn.execute(
        "UPDATE correlation_contexts SET active_incident_id=NULL,reset_at=%s,reset_order=%s WHERE tenant_id=%s AND id=%s AND active_incident_id=%s",
        (now, order, incident["tenant_id"], incident["context_id"], incident["id"]),
    )
    conn.execute(
        "DELETE FROM correlation_evidence WHERE tenant_id=%s AND context_id=%s",
        (incident["tenant_id"], incident["context_id"]),
    )


def reopen_context(conn, incident):
    if incident["context_id"] is None:
        return
    context = conn.execute(
        "SELECT * FROM correlation_contexts WHERE tenant_id=%s AND id=%s",
        (incident["tenant_id"], incident["context_id"]),
    ).fetchone()
    if context is None or context["active_incident_id"] not in (None, incident["id"]):
        raise AppError(
            "context_conflict", "The original correlation context has another active incident.", 409
        )
    conn.execute(
        "UPDATE correlation_contexts SET active_incident_id=%s WHERE tenant_id=%s AND id=%s",
        (incident["id"], incident["tenant_id"], context["id"]),
    )


@dataclass(frozen=True)
class Prepared:
    tenant: UUID
    rows: tuple
    programs: dict
    capacity: dict
    maintenance: object


def prepare_tenant(database, tenant, profile, *, maintenance_input=None, alert_ids=()):
    from keep.maintenance.runtime import prepare_for_tenant

    limits = repo.limits(profile)
    with database.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SELECT set_config('keep.tenant_id',%s,true)", (str(tenant),))
        enabled = conn.execute(
            "SELECT * FROM correlation_rules WHERE tenant_id=%s AND enabled AND deleted_at IS NULL ORDER BY created_at,id LIMIT %s",
            (tenant, limits["enabled_rules_per_tenant"] + 1),
        ).fetchall()
        if len(enabled) > limits["enabled_rules_per_tenant"]:
            raise unavailable("correlation_enabled_capacity")
        rows = repo.with_conditions(
            conn, tenant, [row for row in enabled if not row["kafka_schema_blocked"]]
        )
        supports = conn.execute(
            """SELECT DISTINCT e.alert_id FROM correlation_evidence e JOIN correlation_rules r
            ON r.tenant_id=e.tenant_id AND r.id=e.rule_id AND r.epoch=e.epoch
            WHERE e.tenant_id=%s AND e.expires_at>clock_timestamp() LIMIT %s""",
            (tenant, limits["live_evidence_per_tenant"] + 1),
        ).fetchall()
        if len(supports) > limits["live_evidence_per_tenant"]:
            raise unavailable("correlation_evidence_capacity")
    # Rule revisions are rechecked under the coordinator by worker_turn.
    programs = {
        row["id"]: repo.compile_conditions(repo.definition(row), reuse=True) for row in rows
    }
    for row in rows:
        costs = [p.rule_cost_upper_bound for p in programs[row["id"]].values()]
        if max(costs) > limits["condition_cost"] or sum(costs) > limits["rule_cost"]:
            raise unavailable("correlation_cost_capacity")
    if sum(row["evaluation_cost"] for row in rows) > limits["tenant_cost"]:
        raise unavailable("correlation_tenant_cost_capacity")
    supplied_ids = {str(value) for value in alert_ids}
    support_ids = {str(row["alert_id"]) for row in supports}
    targets = tuple(supplied_ids | support_ids)
    needs_attachment_preparation = bool(support_ids - supplied_ids)
    maintenance = (
        maintenance_input
        if maintenance_input is not None and not needs_attachment_preparation
        else prepare_for_tenant(database, tenant, profile, inline=False, alert_ids=targets)
    )
    if maintenance_input is not None and needs_attachment_preparation:
        if (
            maintenance is None
            or maintenance.generation != maintenance_input.generation
            or maintenance.source_release_since != maintenance_input.source_release_since
        ):
            raise unavailable("maintenance_catalog_changed")
        # Inline source preparation may include a predicted late input. Preserve
        # that exact proof while adding every possible decision attachment's
        # active cause segments/checkpoints before acquiring writer locks.
        segments = {segment.id: segment for segment in maintenance.segments}
        segments.update({segment.id: segment for segment in maintenance_input.segments})
        maintenance = replace(
            maintenance_input,
            segments=tuple(sorted(segments.values(), key=lambda value: value.activation)),
            history_complete=maintenance.history_complete or maintenance_input.history_complete,
            replays={**(maintenance.replays or {}), **(maintenance_input.replays or {})},
        )
    return Prepared(UUID(str(tenant)), rows, programs, limits, maintenance)


def _fields(row):
    # Older journal rows and maintenance proof have no stored name (REV-54).
    result = {key: alert_name(row) if key == "name" else row[key] for key in RULE_FIELDS}
    for key, value in result.items():
        if isinstance(value, UUID):
            result[key] = str(value)
    if isinstance(result["time_created"], str):
        result["time_created"] = datetime.fromisoformat(result["time_created"])
    return result


def _snapshot(row, owner=None):
    return Snapshot(
        UUID(str(row["id"])),
        UUID(str(row["tenant_id"])),
        int(row["revision"]),
        _fields(row),
        row["status"],
        # A recorded dismissal holds like a stored maintenance cause until a
        # source input or command clears it (REV-49).
        correlation_suppressed(row),
        owner,
    )


def _next(conn, tenant, position):
    event = conn.execute(
        "SELECT change_order,'journal' AS stream FROM correlation_journal WHERE tenant_id=%s AND change_order>%s UNION ALL SELECT change_order,'effect' AS stream FROM maintenance_effect_outbox WHERE tenant_id=%s AND change_order>%s ORDER BY change_order LIMIT 1",
        (tenant, position, tenant, position),
    ).fetchone()
    if not event:
        return None
    table = "correlation_journal" if event["stream"] == "journal" else "maintenance_effect_outbox"
    return {
        **conn.execute(
            "SELECT * FROM " + table + " WHERE tenant_id=%s AND change_order=%s",
            (tenant, event["change_order"]),
        ).fetchone(),
        "stream": event["stream"],
    }


def _context(row):
    return Context(
        row["tenant_id"],
        row["rule_id"],
        row["grouping_generation"],
        GroupKey(bytes(row["group_key"])),
    )


def _replay_transitions(conn, prepared, current):
    from keep.maintenance.processing import suppression_at

    tenant, alert_id = prepared.tenant, current["id"]
    maximum = prepared.maintenance.max_inputs
    rows = conn.execute(
        "SELECT * FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s ORDER BY effective_at,original_order LIMIT %s",
        (tenant, alert_id, maximum + 1),
    ).fetchall()
    effects = conn.execute(
        "SELECT q.id AS qualifier_id,e.* FROM maintenance_qualifier_effects q LEFT JOIN LATERAL (SELECT * FROM maintenance_effect_outbox o WHERE o.tenant_id=q.tenant_id AND o.alert_id=q.alert_id AND o.qualifier_id=q.id AND action='activate' ORDER BY change_order DESC LIMIT 1) e ON true WHERE q.tenant_id=%s AND q.alert_id=%s AND q.active ORDER BY q.effective_at,q.id LIMIT %s",
        (tenant, alert_id, maximum + 1),
    ).fetchall()
    if (
        len(rows) > maximum
        or len(effects) > maximum
        or len(rows) + len(effects) > prepared.maintenance.max_work
    ):
        raise CorrelationProofError("correlation_replay_capacity_exceeded")
    events = []
    for row in rows:
        proof = suppression_at(conn, tenant, alert_id, row["effective_at"], row["original_order"])
        events.append(
            ReplayTransition(
                row["id"],
                Boundary(row["effective_at"], row["original_order"]),
                _fields(row["before_snapshot"]) if row["before_snapshot"] else None,
                _fields(row["after_snapshot"]),
                proof.before,
                proof.after,
                False,
                row["new_logical_alert"],
            )
        )
    for effect in effects:
        if effect["id"] is None:
            raise CorrelationProofError("correlation_qualifier_proof_missing")
        fields = _fields(effect["after_snapshot"])
        events.append(
            ReplayTransition(
                effect["qualifier_id"],
                Boundary(effect["effective_at"], effect["original_order"]),
                fields,
                fields,
                True,
                False,
                effect["scheduled"],
                False,
            )
        )
    # A source/control transition is evaluated before its derived unsuppression
    # at the identical boundary. Scheduled end order zero precedes source orders.
    events.sort(
        key=lambda item: (
            item.boundary.at,
            item.boundary.order,
            not item.new_logical_alert,
            item.before == item.after,
            item.id.bytes,
        )
    )
    return tuple(events)


def _replay_states(conn, prepared, states, event, current, owner, now, active, resets, releases):
    # Current state may already include later committed canonical inputs. Keep
    # this alert ineligible until its last entry; do not stamp stale fields with
    # a later revision or steal another rule's earlier ready decision.
    later = conn.execute(
        "SELECT 1 FROM correlation_journal WHERE tenant_id=%s AND alert_id=%s AND change_order>%s UNION ALL SELECT 1 FROM maintenance_effect_outbox WHERE tenant_id=%s AND alert_id=%s AND change_order>%s LIMIT 1",
        (
            prepared.tenant,
            current["id"],
            event["change_order"],
            prepared.tenant,
            current["id"],
            event["change_order"],
        ),
    ).fetchone()
    if later:
        return tuple(
            replace(
                state,
                memberships=tuple(m for m in state.memberships if m.alert_id != current["id"]),
                last_change_order=event["change_order"],
            )
            for state in states
        )
    proof = _replay_transitions(conn, prepared, current)
    budget = Budgets(
        prepared.capacity["live_groups_per_rule"], prepared.capacity["live_evidence_per_rule"]
    )
    remaining = sum(len(s.memberships) for s in states)
    output = []
    for state in sorted(states, key=lambda s: (s.rule.created_at, s.rule.id.bytes)):
        remaining -= len(state.memberships)
        state = replay_alert(
            state,
            _snapshot(current, owner),
            proof,
            now=now,
            change_order=event["change_order"],
            budgets=budget,
            active_contexts=active,
            context_boundaries=resets,
            release_boundaries=releases,
        )
        if remaining + len(state.memberships) > prepared.capacity["live_evidence_per_tenant"]:
            state = replace(
                state,
                rule=replace(state.rule, health="blocked"),
                memberships=(),
                blocked_reason="tenant_evidence_capacity_exceeded",
            )
        remaining += len(state.memberships)
        output.append(state)
    return tuple(output)


@dataclass(frozen=True)
class EvidenceSnapshot:
    rows: tuple
    contexts: dict
    at: datetime


def _load(conn, prepared, position, now, *, event=None, bounded=False):
    tenant = prepared.tenant
    evidence = conn.execute(
        "SELECT e.* FROM correlation_evidence e JOIN correlation_rules r ON r.tenant_id=e.tenant_id AND r.id=e.rule_id AND r.epoch=e.epoch WHERE e.tenant_id=%s AND e.expires_at>%s ORDER BY e.rule_id,e.context_id,e.condition_id,e.alert_id LIMIT %s",
        (tenant, now, prepared.capacity["live_evidence_per_tenant"] + 1),
    ).fetchall()
    if len(evidence) > prepared.capacity["live_evidence_per_tenant"]:
        raise unavailable("correlation_evidence_capacity")
    requested = []
    for row in prepared.rows if event and bounded else ():
        for value in (event.get("before_snapshot"), event.get("after_snapshot")):
            if value is not None:
                key = group_key(repo.grouping(row["group_by"]), value)
                if key is not None:
                    requested.append(
                        {
                            "rule_id": row["id"],
                            "grouping_generation": row["grouping_generation"],
                            "group_digest": key.digest.hex(),
                        }
                    )
    contexts = conn.execute(
        """SELECT * FROM correlation_contexts c WHERE tenant_id=%s AND (%s OR id=ANY(%s::uuid[]))
        UNION SELECT c.* FROM jsonb_to_recordset(%s) AS d(
          rule_id uuid,grouping_generation bigint,group_digest text)
          JOIN correlation_contexts c ON c.tenant_id=%s AND c.rule_id=d.rule_id
          AND c.grouping_generation=d.grouping_generation AND c.group_digest=decode(d.group_digest,'hex')""",
        (
            tenant,
            not bounded,
            list({row["context_id"] for row in evidence}),
            Jsonb(wire(requested)),
            tenant,
        ),
    ).fetchall()
    by_id = {row["id"]: _context(row) for row in contexts}
    active = {
        by_id[row["id"]]: row["active_incident_id"] for row in contexts if row["active_incident_id"]
    }
    resets = {
        by_id[row["id"]]: Boundary(row["reset_at"], row["reset_order"])
        for row in contexts
        if row["reset_at"]
    }
    releases = {
        row["alert_id"]: Boundary(row["effective_at"], row["order_token"])
        for row in conn.execute(
            "SELECT * FROM correlation_boundaries WHERE tenant_id=%s AND (%s OR alert_id=ANY(%s::uuid[]))",
            (
                tenant,
                not bounded,
                list(
                    {row["alert_id"] for row in evidence}
                    | ({event["alert_id"]} if event else set())
                ),
            ),
        )
    }
    states = []
    for row in prepared.rows:
        rule = repo.core_rule(row, prepared.programs[row["id"]])
        members = tuple(
            Membership(
                by_id[m["context_id"]],
                m["epoch"],
                m["condition_id"],
                m["alert_id"],
                m["start_at"],
                m["expires_at"],
                m["observed_revision"],
                m["qualifier_ref"],
            )
            for m in evidence
            if m["rule_id"] == rule.id
        )
        states.append(EvidenceState(rule, members, position, row["blocked_reason"]))
    return (
        tuple(states),
        active,
        resets,
        releases,
        EvidenceSnapshot(tuple(evidence), {by_id[row["id"]]: row["id"] for row in contexts}, now),
    )


def _event(conn, event, current, owner, prepared):
    tenant = prepared.tenant
    if event["stream"] == "effect":
        return maintenance_input(conn, event, current, owner, event["change_order"])
    before, after = event["before_snapshot"], event["after_snapshot"]
    if after.get("retired"):
        return None
    source_order = event["original_order"]
    kind = "source" if event["cause"] == "source" else "manual" if source_order else "bookkeeping"
    if event["cause"] == "maintenance-materialization":
        kind = "bookkeeping"
    if _fields(after) == _fields(current) and correlation_suppressed(
        after
    ) == correlation_suppressed(current):
        after = dict(after, revision=current["revision"])
    if prepared.maintenance and source_order and kind != "bookkeeping":
        from keep.maintenance.processing import suppression_at

        proof = suppression_at(conn, tenant, event["alert_id"], event["effective_at"], source_order)
        before = (
            dict(before, suppressed=proof.before or dismissal_recorded(before)) if before else None
        )
        after = dict(after, suppressed=proof.after or dismissal_recorded(after))
        if after["suppressed"] and not correlation_suppressed(current):
            release = conn.execute(
                """SELECT q.*,i.original_order FROM maintenance_qualifier_effects q
                JOIN maintenance_alert_inputs i ON i.tenant_id=q.tenant_id AND i.alert_id=q.alert_id AND i.id=q.origin_input_id
                WHERE q.tenant_id=%s AND q.alert_id=%s AND q.active AND q.correlation_allowed
                AND q.effective_at>=%s AND i.original_order<=%s ORDER BY q.effective_at LIMIT 1""",
                (tenant, current["id"], event["effective_at"], source_order),
            ).fetchone()
            if release:
                value = maintenance_input(
                    conn, release, current, owner, event["change_order"], source_order
                )
                if value:
                    conn.execute(
                        "UPDATE maintenance_effect_outbox SET processed_at=clock_timestamp() WHERE tenant_id=%s AND alert_id=%s AND qualifier_id=%s AND processed_at IS NULL",
                        (tenant, current["id"], release["id"]),
                    )
                    return value
    return Input(
        uuid5(tenant, "journal:" + str(event["change_order"])),
        event["change_order"],
        _snapshot(before, owner) if before else None,
        _snapshot(after, owner),
        Boundary(event["effective_at"], source_order or 0),
        kind,
        before is None,
    )


def maintenance_input(conn, effect, current, owner, sequence, consuming_order=None):
    proof = conn.execute(
        """WITH source_proof AS (
        SELECT s.*, EXISTS(SELECT 1 FROM kafka_source_results r JOIN kafka_correlation_events e ON e.event_id=r.changed_event_id
            WHERE r.tenant_id=s.tenant_id AND r.alert_id=s.alert_id AND r.application_order=s.original_order)
            OR (s.recorded_at<=p.cutover_at AND NOT EXISTS(SELECT 1 FROM kafka_source_results r
                WHERE r.tenant_id=s.tenant_id AND r.alert_id=s.alert_id AND r.application_order=s.original_order)) AS consumed
        FROM maintenance_alert_inputs s CROSS JOIN kafka_pipeline_control p
        WHERE s.tenant_id=%s AND s.alert_id=%s AND s.kind='source')
        SELECT q.*,i.after_snapshot,i.original_order AS snapshot_order,o.original_order AS origin_order,o.consumed AS origin_consumed,
        EXISTS(SELECT 1 FROM maintenance_cause_history h WHERE h.tenant_id=q.tenant_id AND h.alert_id=q.alert_id
            AND h.boundary_kind='close' AND h.boundary_id=o.id::text AND h.effective_at=q.effective_at) AS source_release,
        NOT EXISTS(SELECT 1 FROM source_proof s WHERE s.original_order<>coalesce(%s,-1)
            AND NOT coalesce(s.consumed,false)) AS snapshot_consumed
        FROM maintenance_qualifier_effects q
        JOIN maintenance_alert_inputs i ON i.tenant_id=q.tenant_id AND i.alert_id=q.alert_id AND i.id=q.source_input_id
        JOIN source_proof o ON o.id=q.origin_input_id
        WHERE q.tenant_id=%s AND q.alert_id=%s AND q.id=%s AND q.active AND q.correlation_allowed""",
        (
            current["tenant_id"],
            current["id"],
            consuming_order,
            current["tenant_id"],
            current["id"],
            effect.get("qualifier_id", effect["id"]),
        ),
    ).fetchone()
    if (
        not proof
        or not proof["snapshot_consumed"]
        or not (proof["origin_consumed"] or proof["origin_order"] == consuming_order)
    ):
        return None
    if (
        correlation_suppressed(current)
        or current["status"] != "firing"
        or _fields(proof["after_snapshot"]) != _fields(current)
    ):
        # A maintenance release during an active dismissal creates no qualifier.
        return None
    before = _snapshot(dict(current, suppressed=True), owner)
    after = _snapshot(current, owner)
    reset = conn.execute(
        """SELECT max(original_order) AS original_order FROM maintenance_alert_inputs
        WHERE tenant_id=%s AND alert_id=%s AND kind<>'source' AND original_order<=%s AND effective_at<=%s
        AND before_snapshot->>'status'<>after_snapshot->>'status'""",
        (current["tenant_id"], current["id"], proof["snapshot_order"], proof["effective_at"]),
    ).fetchone()["original_order"]
    provenance = None
    if reset is not None:
        rows = conn.execute(
            """SELECT id,before_snapshot,after_snapshot,effective_at FROM maintenance_alert_inputs
            WHERE tenant_id=%s AND alert_id=%s AND kind='source' AND original_order>%s AND original_order<=%s
            AND effective_at<=%s ORDER BY original_order""",
            (
                current["tenant_id"],
                current["id"],
                reset,
                proof["snapshot_order"],
                proof["effective_at"],
            ),
        ).fetchall()
        provenance = tuple(
            (
                _fields(row["before_snapshot"]) if row["before_snapshot"] else None,
                _fields(row["after_snapshot"]),
                row["effective_at"],
                proof["source_release"] and row["id"] == proof["origin_input_id"],
            )
            for row in rows
        )
    return Input(
        proof["id"],
        sequence,
        before,
        after,
        Boundary(proof["effective_at"], 0),
        "scheduled",
        False,
        True,
        provenance,
    )


def lock_decision_scope(conn, tenant, targets, *, incidents=(), contexts_locked=False):
    """Prelock a bounded live-evidence decision scope before mutating a target.

    Pass contexts_locked=True only when the caller already ran lock_contexts in
    this transaction with live=True and the same targets and incidents (or a
    superset), such as lock_catalog with inline correlation.
    """
    if not contexts_locked:
        lock_contexts(conn, tenant, targets=targets, incidents=incidents)
    ids = {UUID(str(value)) for value in targets}
    ids.update(
        row["alert_id"]
        for row in conn.execute(
            """SELECT DISTINCT e.alert_id FROM correlation_evidence e JOIN correlation_rules r
            ON r.tenant_id=e.tenant_id AND r.id=e.rule_id AND r.epoch=e.epoch
            WHERE e.tenant_id=%s AND e.expires_at>clock_timestamp()""",
            (tenant,),
        )
    )
    conn.execute(
        """SELECT id FROM incidents WHERE tenant_id=%s AND (id=ANY(%s::uuid[]) OR id IN
        (SELECT c.active_incident_id FROM correlation_evidence e JOIN correlation_contexts c
         ON c.tenant_id=e.tenant_id AND c.id=e.context_id JOIN correlation_rules r
         ON r.tenant_id=e.tenant_id AND r.id=e.rule_id AND r.epoch=e.epoch
         WHERE e.tenant_id=%s AND e.expires_at>clock_timestamp()) OR id IN
        (SELECT incident_id FROM incident_alert_links WHERE tenant_id=%s AND alert_id=ANY(%s::uuid[]) AND unlinked_at IS NULL)) ORDER BY id FOR UPDATE""",
        (tenant, list(incidents), tenant, tenant, sorted(ids)),
    ).fetchall()
    conn.execute(
        "SELECT id FROM alerts WHERE tenant_id=%s AND id=ANY(%s::uuid[]) ORDER BY id FOR UPDATE",
        (tenant, sorted(ids)),
    ).fetchall()


def _persist(conn, prepared, states, previous):
    """Persist only membership deltas, in two bounded SQL batches.

    The snapshot and writes share the tenant coordinator transaction. Unchanged
    support keeps its original start/expiry and is neither deleted nor rewritten.
    Context lookup is once per newly encountered group, never per membership.
    """
    columns = ("rule_id", "epoch", "context_id", "condition_id", "alert_id")
    values = ("qualifier_ref", "start_at", "expires_at", "observed_revision")
    old = {tuple(row[key] for key in columns): row for row in previous.rows}
    contexts = dict(previous.contexts)
    desired = {}
    for state in states:
        rule = state.rule
        row = next(row for row in prepared.rows if row["id"] == rule.id)
        for member in state.memberships:
            context = contexts.get(member.context)
            if context is None:
                context = repo.ensure_context(
                    conn, row, member.context.group, max_bucket=prepared.capacity["digest_bucket"]
                )
                contexts[member.context] = context
            key = (rule.id, rule.epoch, context, member.condition_id, member.alert_id)
            desired[key] = dict(
                zip(
                    columns + values,
                    (*key, member.input_id, member.start, member.expiry, member.observed_revision),
                )
            )
        if state.blocked_reason != row["blocked_reason"] or rule.health != row["health"]:
            conn.execute(
                "UPDATE correlation_rules SET health=%s,blocked_reason=%s WHERE tenant_id=%s AND id=%s",
                (rule.health, state.blocked_reason, prepared.tenant, rule.id),
            )
    removed = [dict(zip(columns, key)) for key in old.keys() - desired.keys()]
    changed = [
        row
        for key, row in desired.items()
        if key not in old or any(row[name] != old[key][name] for name in values)
    ]
    # The loader excludes expired/old-epoch evidence. Prune that excluded set as
    # well, rather than retaining it forever after replacing full-rule deletes.
    conn.execute(
        """DELETE FROM correlation_evidence e WHERE e.tenant_id=%s AND
        (e.expires_at<=%s OR NOT EXISTS(SELECT 1 FROM correlation_rules r
          WHERE r.tenant_id=e.tenant_id AND r.id=e.rule_id AND r.epoch=e.epoch))""",
        (prepared.tenant, previous.at),
    )
    if removed:
        conn.execute(
            """DELETE FROM correlation_evidence e USING jsonb_to_recordset(%s) AS d(
            rule_id uuid,epoch bigint,context_id uuid,condition_id uuid,alert_id uuid)
            WHERE e.tenant_id=%s AND (e.rule_id,e.epoch,e.context_id,e.condition_id,e.alert_id)=
            (d.rule_id,d.epoch,d.context_id,d.condition_id,d.alert_id)""",
            (Jsonb(wire(removed)), prepared.tenant),
        )
    if changed:
        conn.execute(
            """INSERT INTO correlation_evidence(tenant_id,rule_id,epoch,context_id,condition_id,
            alert_id,qualifier_ref,start_at,expires_at,observed_revision)
            SELECT %s,d.* FROM jsonb_to_recordset(%s) AS d(rule_id uuid,epoch bigint,
            context_id uuid,condition_id uuid,alert_id uuid,qualifier_ref uuid,
            start_at timestamptz,expires_at timestamptz,observed_revision bigint)
            ON CONFLICT(tenant_id,rule_id,epoch,context_id,condition_id,alert_id) DO UPDATE SET
            qualifier_ref=EXCLUDED.qualifier_ref,start_at=EXCLUDED.start_at,
            expires_at=EXCLUDED.expires_at,observed_revision=EXCLUDED.observed_revision""",
            (prepared.tenant, Jsonb(wire(changed))),
        )


def _commit_decision(conn, prepared, decision, position, alerts):
    from keep.incidents.state import activity, alert_link_change, get_incident, update_tokens

    tenant = prepared.tenant
    row = next(r for r in prepared.rows if r["id"] == decision.context.rule_id)
    context = repo.ensure_context(
        conn, row, decision.context.group, max_bucket=prepared.capacity["digest_bucket"]
    )
    incident = decision.existing_incident_id or uuid4()
    new = decision.existing_incident_id is None
    if new:
        cycle = uuid4()
        conn.execute(
            "INSERT INTO incident_identities(id,tenant_id) VALUES(%s,%s)", (incident, tenant)
        )
        conn.execute(
            "INSERT INTO incidents(id,tenant_id,title,description,severity,status,origin,context_id,cycle_id,created_at,updated_at,last_activity) VALUES(%s,%s,%s,%s,%s,'open','correlation',%s,%s,%s,%s,%s)",
            (
                incident,
                tenant,
                row["name"],
                row["description"],
                row["severity"],
                context,
                cycle,
                decision.decision_time,
                decision.decision_time,
                decision.decision_time,
            ),
        )
        conn.execute(
            "INSERT INTO incident_cycles(tenant_id,incident_id,id,opened_at) VALUES(%s,%s,%s,%s)",
            (tenant, incident, cycle, decision.decision_time),
        )
        conn.execute(
            "UPDATE correlation_contexts SET active_incident_id=%s WHERE tenant_id=%s AND id=%s",
            (incident, tenant, context),
        )
    target = get_incident(conn, tenant, incident)
    for alert_id in decision.attachment_ids:
        conn.execute(
            "INSERT INTO incident_alert_links(tenant_id,incident_id,alert_id,linked_at) VALUES(%s,%s,%s,%s) ON CONFLICT(tenant_id,incident_id,alert_id) DO UPDATE SET linked_at=EXCLUDED.linked_at,unlinked_at=NULL",
            (tenant, incident, alert_id, decision.decision_time),
        )
        conn.execute(
            "INSERT INTO alert_active_ownership(tenant_id,alert_id,incident_id) VALUES(%s,%s,%s)",
            (tenant, alert_id, incident),
        )
        alert_link_change(
            conn,
            alerts[alert_id],
            decision.decision_time,
            None,
            "correlation-link",
            prepared.maintenance,
        )
        # Keep original starts for the winning context, discard competitors.
        updated = conn.execute(
            "SELECT revision FROM alerts WHERE tenant_id=%s AND id=%s", (tenant, alert_id)
        ).fetchone()["revision"]
        conn.execute(
            "DELETE FROM correlation_evidence WHERE tenant_id=%s AND alert_id=%s AND context_id<>%s",
            (tenant, alert_id, context),
        )
        conn.execute(
            "UPDATE correlation_evidence SET observed_revision=%s WHERE tenant_id=%s AND alert_id=%s AND context_id=%s",
            (updated, tenant, alert_id, context),
        )
    proof = {
        "rule_id": row["id"],
        "rule_revision": row["revision"],
        "epoch": row["epoch"],
        "grouping_generation": row["grouping_generation"],
        "group": json.loads(decision.context.group.canonical),
        "decision_time": decision.decision_time,
        "attachments": decision.attachment_ids,
        "supports": [
            {
                "condition_id": m.condition_id,
                "alert_id": m.alert_id,
                "qualifier_id": m.input_id,
                "start": m.start,
                "expires_at": m.expiry,
            }
            for m in decision.supports
        ],
    }
    decision_id = uuid4()
    conn.execute(
        "INSERT INTO correlation_decisions(id,tenant_id,rule_id,rule_revision,epoch,context_id,incident_id,decision_at,observed_change_order,evidence) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            decision_id,
            tenant,
            row["id"],
            row["revision"],
            row["epoch"],
            context,
            incident,
            decision.decision_time,
            position,
            Jsonb(wire(proof)),
        ),
    )
    conn.execute(
        "INSERT INTO correlation_revision_holds(tenant_id,rule_id,revision,consumer_kind,reference) VALUES(%s,%s,%s,'incident',%s) ON CONFLICT DO NOTHING",
        (tenant, row["id"], row["revision"], str(incident)),
    )
    activity(
        conn,
        target,
        decision.decision_time,
        None,
        "correlation-created" if new else "correlation-added",
        dict(proof, decision_id=decision_id),
    )
    if new:
        update_tokens(conn, tenant, incident)
    return incident


def _active_links(conn, tenant, incident_ids):
    """Currently linked alerts per incident, in one statement (formerly one each).

    Every requested incident gets an entry, empty when nothing is linked, in
    ``incident_ids`` order. Empty input issues no statement.
    """
    if not incident_ids:
        return {}
    linked = {str(incident): set() for incident in incident_ids}
    for row in conn.execute(
        "SELECT incident_id,alert_id FROM incident_alert_links WHERE tenant_id=%s AND incident_id=ANY(%s::uuid[]) AND unlinked_at IS NULL",
        (tenant, list(incident_ids)),
    ):
        linked[str(row["incident_id"])].add(row["alert_id"])
    return {incident: frozenset(linked[str(incident)]) for incident in incident_ids}


def worker_turn(
    database,
    tenant,
    profile,
    *,
    prepared_input=None,
    input_event=None,
    transaction=None,
    kafka=False,
):
    prepared = prepared_input or prepare_tenant(database, tenant, profile)
    with (
        nullcontext(transaction)
        if transaction is not None
        else database.transaction(tenant) as conn
    ):
        _, now = coordinator(conn, tenant)
        lock_contexts(conn, tenant, targets=())
        current = conn.execute(
            "SELECT id,revision,health,blocked_reason FROM correlation_rules WHERE tenant_id=%s AND enabled AND NOT kafka_schema_blocked AND deleted_at IS NULL ORDER BY created_at,id",
            (tenant,),
        ).fetchall()
        if [(r["id"], r["revision"]) for r in current] != [
            (r["id"], r["revision"]) for r in prepared.rows
        ]:
            raise unavailable("correlation_compiled_revision_changed")
        # Health is runtime state and can change without a configuration revision.
        # A second worker must never resurrect a rule blocked by the first turn.
        # Equal revisions prove every other column and condition is unchanged, so
        # only health is refreshed, on copies: callers reuse the prepared input.
        prepared = replace(
            prepared,
            rows=tuple(
                dict(row, health=fresh["health"], blocked_reason=fresh["blocked_reason"])
                for row, fresh in zip(prepared.rows, current)
            ),
        )
        consumer = conn.execute(
            "SELECT * FROM correlation_consumer_state WHERE tenant_id=%s FOR UPDATE", (tenant,)
        ).fetchone()
        if not consumer:
            return 0
        position = consumer["kafka_sequence"] if kafka else consumer["change_order"]
        event = (
            dict(input_event, change_order=position + 1)
            if input_event
            else None
            if kafka
            else _next(conn, tenant, position)
        )
        states, active, resets, releases, persisted = _load(
            conn, prepared, position, now, event=event, bounded=kafka
        )
        ids = {m.alert_id for state in states for m in state.memberships}
        if event:
            ids.add(event["alert_id"])
        incident_ids = sorted(set(active.values()))
        conn.execute(
            "SELECT id FROM incidents WHERE tenant_id=%s AND id=ANY(%s::uuid[]) ORDER BY id FOR UPDATE",
            (tenant, incident_ids),
        ).fetchall()
        rows = conn.execute(
            "SELECT a.* FROM alerts a JOIN alert_identities i ON i.tenant_id=a.tenant_id AND i.id=a.id AND i.retired_at IS NULL WHERE a.tenant_id=%s AND a.id=ANY(%s::uuid[]) ORDER BY a.id FOR UPDATE OF a",
            (tenant, sorted(ids)),
        ).fetchall()
        alerts = {row["id"]: row for row in rows}
        from keep.alerts.state import pending

        for row in rows:
            pending(conn, tenant, row)
        owners = {
            row["alert_id"]: row["incident_id"]
            for row in conn.execute(
                "SELECT * FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=ANY(%s::uuid[])",
                (tenant, sorted(ids)),
            )
        }
        unsafe_suppression = set()
        if prepared.maintenance:
            from keep.maintenance.processing import derive_current_many

            # One statement for every loaded alert (formerly one per alert).
            for row, (suppressed, _) in zip(rows, derive_current_many(conn, tenant, rows, now)):
                if suppressed != row["suppressed"]:
                    unsafe_suppression.add(row["id"])
        if event:
            if event["alert_id"] not in alerts:
                states = tuple(
                    replace(
                        s,
                        memberships=tuple(
                            m for m in s.memberships if m.alert_id != event["alert_id"]
                        ),
                        last_change_order=event["change_order"],
                    )
                    for s in states
                )
            else:
                try:
                    if prepared.maintenance and not kafka:
                        states = _replay_states(
                            conn,
                            prepared,
                            states,
                            event,
                            alerts[event["alert_id"]],
                            owners.get(event["alert_id"]),
                            now,
                            active,
                            resets,
                            releases,
                        )
                        value = None
                    else:
                        value = _event(
                            conn,
                            event,
                            alerts[event["alert_id"]],
                            owners.get(event["alert_id"]),
                            prepared,
                        )
                    if value:
                        states = apply_all(
                            states,
                            value,
                            now=now,
                            budgets=Budgets(
                                prepared.capacity["live_groups_per_rule"],
                                prepared.capacity["live_evidence_per_rule"],
                            ),
                            tenant_evidence_budget=prepared.capacity["live_evidence_per_tenant"],
                            active_contexts=active,
                            context_boundaries=resets,
                            release_boundaries=releases,
                        )
                except CorrelationProofError as error:
                    if kafka:
                        raise unavailable("correlation_transition_proof_invalid") from error
                    conn.execute(
                        "UPDATE correlation_consumer_state SET health='recovery_needed',blocked_reason=%s,pending=true,updated_at=%s WHERE tenant_id=%s",
                        (str(error), now, tenant),
                    )
                    return 0
            position = event["change_order"]
        _persist(conn, prepared, states, persisted)
        # Final time is sampled after all decision locks, and cannot go backwards.
        decision_now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        if decision_now < now:
            raise unavailable("clock_untrusted")
        snapshots = {key: _snapshot(row, owners.get(key)) for key, row in alerts.items()}
        for key in unsafe_suppression:
            snapshots[key] = replace(snapshots[key], suppressed=True)
        links = _active_links(conn, tenant, incident_ids)
        decision = choose_decision(
            states, snapshots, now=decision_now, active_contexts=active, linked_alerts=links
        )
        if decision:
            _commit_decision(conn, prepared, decision, position, alerts)
        more = bool(decision) if kafka else bool(decision or _next(conn, tenant, position))
        conn.execute(
            "UPDATE correlation_consumer_state SET "
            + ("kafka_sequence" if kafka else "change_order")
            + "=%s,pending=%s,health='healthy',blocked_reason='',updated_at=%s WHERE tenant_id=%s",
            (position, more, decision_now, tenant),
        )
        if event and event["stream"] == "effect" and not kafka:
            conn.execute(
                "UPDATE maintenance_effect_outbox SET processed_at=%s WHERE tenant_id=%s AND id=%s",
                (decision_now, tenant, event["id"]),
            )
        return int(bool(event or decision))
