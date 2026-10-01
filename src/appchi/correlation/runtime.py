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

from appchi.cel.catalog import CORRELATION_FIELDS as RULE_FIELDS
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import coordinator, wire
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
)


def lock_contexts(conn, tenant):
    """All ownership writers call after coordinator, before incident/alert locks."""
    conn.execute(
        "SELECT id FROM correlation_rules WHERE tenant_id=%s ORDER BY id FOR UPDATE", (tenant,)
    ).fetchall()
    conn.execute(
        "SELECT id FROM correlation_contexts WHERE tenant_id=%s ORDER BY rule_id,grouping_generation,group_key,id FOR UPDATE",
        (tenant,),
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


def prepare_tenant(database, tenant, profile, *, allow_local_preview=False, maintenance_input=None):
    from appchi.maintenance.runtime import prepare_for_tenant

    limits = repo.limits(profile, allow_local_preview=allow_local_preview)
    with database.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SELECT set_config('appchi.tenant_id',%s,true)", (str(tenant),))
        ids = conn.execute(
            "SELECT id FROM correlation_rules WHERE tenant_id=%s AND enabled AND deleted_at IS NULL ORDER BY created_at,id LIMIT %s",
            (tenant, limits["enabled_rules_per_tenant"] + 1),
        ).fetchall()
        if len(ids) > limits["enabled_rules_per_tenant"]:
            raise unavailable("correlation_enabled_capacity")
        rows = tuple(row for item in ids if not (row := repo.get_rule(conn, tenant, item["id"]))["kafka_schema_blocked"])
    programs = {row["id"]: repo.compile_conditions(repo.definition(row)) for row in rows}
    for row in rows:
        costs = [p.rule_cost_upper_bound for p in programs[row["id"]].values()]
        if max(costs) > limits["condition_cost"] or sum(costs) > limits["rule_cost"]:
            raise unavailable("correlation_cost_capacity")
    if sum(row["evaluation_cost"] for row in rows) > limits["tenant_cost"]:
        raise unavailable("correlation_tenant_cost_capacity")
    maintenance = maintenance_input or prepare_for_tenant(database, tenant, profile, inline=False)
    if maintenance is None:
        with database.transaction(tenant) as conn:
            if conn.execute(
                "SELECT 1 FROM maintenance_segments WHERE tenant_id=%s LIMIT 1", (tenant,)
            ).fetchone():
                raise unavailable("correlation_maintenance_proof_required")
    return Prepared(UUID(str(tenant)), rows, programs, limits, maintenance)


def _fields(row):
    result = {key: row[key] for key in RULE_FIELDS}
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
        row["suppressed"],
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
    from appchi.maintenance.processing import suppression_at

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


def _load(conn, prepared, position, now):
    tenant = prepared.tenant
    contexts = conn.execute(
        "SELECT * FROM correlation_contexts WHERE tenant_id=%s", (tenant,)
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
            "SELECT * FROM correlation_boundaries WHERE tenant_id=%s", (tenant,)
        )
    }
    evidence = conn.execute(
        "SELECT e.* FROM correlation_evidence e JOIN correlation_rules r ON r.tenant_id=e.tenant_id AND r.id=e.rule_id AND r.epoch=e.epoch WHERE e.tenant_id=%s AND e.expires_at>%s ORDER BY e.rule_id,e.context_id,e.condition_id,e.alert_id LIMIT %s",
        (tenant, now, prepared.capacity["live_evidence_per_tenant"] + 1),
    ).fetchall()
    if len(evidence) > prepared.capacity["live_evidence_per_tenant"]:
        raise unavailable("correlation_evidence_capacity")
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
    return tuple(states), active, resets, releases


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
    if _fields(after) == _fields(current) and after["suppressed"] == current["suppressed"]:
        after = dict(after, revision=current["revision"])
    if prepared.maintenance and source_order and kind != "bookkeeping":
        from appchi.maintenance.processing import suppression_at

        proof = suppression_at(conn, tenant, event["alert_id"], event["effective_at"], source_order)
        before = dict(before, suppressed=proof.before) if before else None
        after = dict(after, suppressed=proof.after)
        if after["suppressed"] and not current["suppressed"]:
            release = conn.execute("""SELECT q.*,i.original_order FROM maintenance_qualifier_effects q
                JOIN maintenance_alert_inputs i ON i.tenant_id=q.tenant_id AND i.alert_id=q.alert_id AND i.id=q.origin_input_id
                WHERE q.tenant_id=%s AND q.alert_id=%s AND q.active AND q.correlation_allowed
                AND q.effective_at>=%s AND i.original_order<=%s ORDER BY q.effective_at LIMIT 1""",
                (tenant, current["id"], event["effective_at"], source_order)).fetchone()
            if release:
                value = maintenance_input(conn, release, current, owner, event["change_order"], source_order)
                if value:
                    conn.execute("UPDATE maintenance_effect_outbox SET processed_at=clock_timestamp() WHERE tenant_id=%s AND alert_id=%s AND qualifier_id=%s AND processed_at IS NULL", (tenant,current["id"],release["id"]))
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
    proof = conn.execute("""WITH source_proof AS (
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
        (current["tenant_id"],current["id"],consuming_order,current["tenant_id"],current["id"],effect.get("qualifier_id", effect["id"]))).fetchone()
    if not proof or not proof["snapshot_consumed"] or not (proof["origin_consumed"] or proof["origin_order"] == consuming_order):
        return None
    if current["suppressed"] or current["status"] != "firing" or _fields(proof["after_snapshot"]) != _fields(current):
        return None
    before = _snapshot(dict(current, suppressed=True), owner)
    after = _snapshot(current, owner)
    reset = conn.execute("""SELECT max(original_order) AS original_order FROM maintenance_alert_inputs
        WHERE tenant_id=%s AND alert_id=%s AND kind<>'source' AND original_order<=%s AND effective_at<=%s
        AND before_snapshot->>'status'<>after_snapshot->>'status'""",
        (current["tenant_id"],current["id"],proof["snapshot_order"],proof["effective_at"])).fetchone()["original_order"]
    provenance = None
    if reset is not None:
        rows = conn.execute("""SELECT id,before_snapshot,after_snapshot,effective_at FROM maintenance_alert_inputs
            WHERE tenant_id=%s AND alert_id=%s AND kind='source' AND original_order>%s AND original_order<=%s
            AND effective_at<=%s ORDER BY original_order""",
            (current["tenant_id"],current["id"],reset,proof["snapshot_order"],proof["effective_at"])).fetchall()
        provenance = tuple((_fields(row["before_snapshot"]) if row["before_snapshot"] else None,
            _fields(row["after_snapshot"]),row["effective_at"],
            proof["source_release"] and row["id"] == proof["origin_input_id"]) for row in rows)
    return Input(proof["id"], sequence, before, after, Boundary(proof["effective_at"],0), "scheduled", False, True, provenance)


def lock_decision_scope(conn, tenant, targets, *, incidents=()):
    """Prelock a bounded live-evidence decision scope before mutating a target."""
    lock_contexts(conn, tenant)
    ids = {UUID(str(value)) for value in targets}
    ids.update(row["alert_id"] for row in conn.execute("SELECT DISTINCT alert_id FROM correlation_evidence WHERE tenant_id=%s", (tenant,)))
    conn.execute("""SELECT id FROM incidents WHERE tenant_id=%s AND (id=ANY(%s::uuid[]) OR id IN
        (SELECT active_incident_id FROM correlation_contexts WHERE tenant_id=%s) OR id IN
        (SELECT incident_id FROM incident_alert_links WHERE tenant_id=%s AND alert_id=ANY(%s::uuid[]) AND unlinked_at IS NULL)) ORDER BY id FOR UPDATE""",
        (tenant,list(incidents),tenant,tenant,sorted(ids))).fetchall()
    conn.execute("SELECT id FROM alerts WHERE tenant_id=%s AND id=ANY(%s::uuid[]) ORDER BY id FOR UPDATE",(tenant,sorted(ids))).fetchall()


def _persist(conn, prepared, states):
    for state in states:
        rule = state.rule
        conn.execute(
            "DELETE FROM correlation_evidence WHERE tenant_id=%s AND rule_id=%s",
            (prepared.tenant, rule.id),
        )
        row = next(row for row in prepared.rows if row["id"] == rule.id)
        for member in state.memberships:
            context = repo.ensure_context(
                conn, row, member.context.group, max_bucket=prepared.capacity["digest_bucket"]
            )
            conn.execute(
                "INSERT INTO correlation_evidence(tenant_id,rule_id,epoch,context_id,condition_id,alert_id,qualifier_ref,start_at,expires_at,observed_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    prepared.tenant,
                    rule.id,
                    rule.epoch,
                    context,
                    member.condition_id,
                    member.alert_id,
                    member.input_id,
                    member.start,
                    member.expiry,
                    member.observed_revision,
                ),
            )
        if state.blocked_reason != row["blocked_reason"] or rule.health != row["health"]:
            conn.execute(
                "UPDATE correlation_rules SET health=%s,blocked_reason=%s WHERE tenant_id=%s AND id=%s",
                (rule.health, state.blocked_reason, prepared.tenant, rule.id),
            )


def _commit_decision(conn, prepared, decision, position, alerts):
    from appchi.incidents.routes import activity, alert_link_change, get_incident, update_tokens

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


def worker_turn(database, tenant, profile, *, allow_local_preview=False, prepared_input=None, input_event=None, transaction=None, kafka=False):
    with nullcontext(transaction) if transaction is not None else database.transaction(tenant) as conn:
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='correlation'"
        ).fetchone()
        if not gate or not gate["ready"]:
            return 0
    preview = {"allow_local_preview": True} if allow_local_preview else {}
    prepared = prepared_input or prepare_tenant(database, tenant, profile, **preview)
    with nullcontext(transaction) if transaction is not None else database.transaction(tenant) as conn:
        _, now = coordinator(conn, tenant)
        if not conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='correlation'"
        ).fetchone()["ready"]:
            return 0
        lock_contexts(conn, tenant)
        current = conn.execute(
            "SELECT id,revision FROM correlation_rules WHERE tenant_id=%s AND enabled AND NOT kafka_schema_blocked AND deleted_at IS NULL ORDER BY created_at,id",
            (tenant,),
        ).fetchall()
        if [(r["id"], r["revision"]) for r in current] != [
            (r["id"], r["revision"]) for r in prepared.rows
        ]:
            raise unavailable("correlation_compiled_revision_changed")
        # Health is runtime state and can change without a configuration revision.
        # A second worker must never resurrect a rule blocked by the first turn.
        prepared = replace(
            prepared, rows=tuple(repo.get_rule(conn, tenant, row["id"]) for row in current)
        )
        consumer = conn.execute(
            "SELECT * FROM correlation_consumer_state WHERE tenant_id=%s FOR UPDATE", (tenant,)
        ).fetchone()
        if not consumer:
            return 0
        position = consumer["kafka_sequence"] if kafka else consumer["change_order"]
        event = dict(input_event, change_order=position + 1) if input_event else None if kafka else _next(conn, tenant, position)
        states, active, resets, releases = _load(conn, prepared, position, now)
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
        from appchi.alerts.routes import pending

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
            from appchi.maintenance.processing import derive_current

            for row in rows:
                suppressed, _ = derive_current(conn, row, now)
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
        _persist(conn, prepared, states)
        # Final time is sampled after all decision locks, and cannot go backwards.
        decision_now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        if decision_now < now:
            raise unavailable("clock_untrusted")
        snapshots = {key: _snapshot(row, owners.get(key)) for key, row in alerts.items()}
        for key in unsafe_suppression:
            snapshots[key] = replace(snapshots[key], suppressed=True)
        links = {
            incident: frozenset(
                row["alert_id"]
                for row in conn.execute(
                    "SELECT alert_id FROM incident_alert_links WHERE tenant_id=%s AND incident_id=%s AND unlinked_at IS NULL",
                    (tenant, incident),
                )
            )
            for incident in incident_ids
        }
        decision = choose_decision(
            states, snapshots, now=decision_now, active_contexts=active, linked_alerts=links
        )
        if decision:
            _commit_decision(conn, prepared, decision, position, alerts)
        more = bool(decision) if kafka else bool(decision or _next(conn, tenant, position))
        conn.execute(
            "UPDATE correlation_consumer_state SET " + ("kafka_sequence" if kafka else "change_order") + "=%s,pending=%s,health='healthy',blocked_reason='',updated_at=%s WHERE tenant_id=%s",
            (position, more, decision_now, tenant),
        )
        if event and event["stream"] == "effect" and not kafka:
            conn.execute(
                "UPDATE maintenance_effect_outbox SET processed_at=%s WHERE tenant_id=%s AND id=%s",
                (decision_now, tenant, event["id"]),
            )
        return int(bool(event or decision))
