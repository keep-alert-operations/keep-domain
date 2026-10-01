"""Correlation algorithms; PostgreSQL must commit the returned state/decision.

No function writes incidents, owns alerts, advances a durable cursor or claims
that its in-memory snapshot is a substitute for the tenant coordinator lock.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import hashlib
import json
from typing import Literal, Protocol
from uuid import UUID

from appchi.cel.catalog import FIELDS, CORRELATION_FIELDS as RULE_FIELDS


class CorrelationProofError(RuntimeError):
    """Missing authoritative prior/order proof requires tenant recovery gating."""


def _aware(at):
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("database-stamped aware time required")


@dataclass(frozen=True)
class Boundary:
    at: datetime
    order: int

    def __post_init__(self):
        _aware(self.at)
        if self.order < 0:
            raise ValueError("invalid tenant order")


@dataclass(frozen=True)
class GroupField:
    name: str
    kind: Literal["string", "int", "bool"]


@dataclass(frozen=True)
class GroupKey:
    """Equality/order use complete canonical bytes, never just a hash digest."""

    canonical: bytes

    @property
    def digest(self):
        return hashlib.sha256(self.canonical).digest()


def validate_group_fields(fields: tuple[GroupField, ...]):
    if len(fields) > 3 or len({f.name for f in fields}) != len(fields):
        raise ValueError("choose at most three distinct grouping fields")
    for selected in fields:
        field = FIELDS.get(selected.name)
        kind = "string" if field and field.kind == "enum" else field.kind if field else None
        if (
            selected.name not in RULE_FIELDS
            or kind not in ("string", "int", "bool")
            or selected.kind != kind
        ):
            raise ValueError("grouping field is not an approved scalar rule field")


def group_key(fields: tuple[GroupField, ...], snapshot: dict) -> GroupKey | None:
    values = []
    for field in fields:
        value = snapshot.get(field.name)
        if field.kind == "string":
            valid = isinstance(value, str) and bool(value.strip())
        elif field.kind == "int":
            valid = type(value) is int and -(2**63) <= value < 2**63
        elif field.kind == "bool":
            valid = type(value) is bool
        else:
            valid = False
        if not valid:
            return None
        values.append([field.name, field.kind, value])
    return GroupKey(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


class Program(Protocol):
    source: str

    def evaluate(self, alert: dict, evaluated_at: datetime) -> bool: ...


@dataclass(frozen=True)
class Condition:
    id: UUID
    label: str
    program: Program


@dataclass(frozen=True)
class Rule:
    id: UUID
    tenant_id: UUID
    created_at: datetime
    revision: int
    epoch: int
    grouping_generation: int
    epoch_boundary: Boundary
    conditions: tuple[Condition, ...]
    grouping: tuple[GroupField, ...] = ()
    window_minutes: int = 10
    enabled: bool = True
    deleted: bool = False
    health: Literal["healthy", "blocked"] = "healthy"

    def __post_init__(self):
        _aware(self.created_at)
        if not 1 <= len(self.conditions) <= 10 or len({c.id for c in self.conditions}) != len(
            self.conditions
        ):
            raise ValueError("one to ten independently identified conditions required")
        if (
            not 1 <= self.window_minutes <= 1440
            or min(self.revision, self.epoch, self.grouping_generation) < 1
        ):
            raise ValueError("invalid rule window or revisions")
        validate_group_fields(self.grouping)


@dataclass(frozen=True)
class Context:
    tenant_id: UUID
    rule_id: UUID
    grouping_generation: int
    group: GroupKey


def context_for(rule: Rule, group: GroupKey) -> Context:
    return Context(rule.tenant_id, rule.id, rule.grouping_generation, group)


@dataclass(frozen=True)
class Snapshot:
    id: UUID
    tenant_id: UUID
    revision: int
    fields: dict
    status: Literal["firing", "resolved"]
    suppressed: bool
    active_incident_id: UUID | None = None

    def __post_init__(self):
        if self.status not in ("firing", "resolved") or self.revision < 1:
            raise ValueError("invalid authoritative alert snapshot")


@dataclass(frozen=True)
class Input:
    id: UUID
    change_order: int
    before: Snapshot | None
    after: Snapshot
    qualifier: Boundary
    kind: Literal["source", "manual", "scheduled", "bookkeeping"]
    new_logical_alert: bool = False
    derived_qualifier: bool = False
    source_provenance: tuple[tuple[dict | None, dict, datetime, bool], ...] | None = None


@dataclass(frozen=True)
class Membership:
    context: Context
    epoch: int
    condition_id: UUID
    alert_id: UUID
    start: datetime
    expiry: datetime
    observed_revision: int
    input_id: UUID


@dataclass(frozen=True)
class ReplayTransition:
    """Original field/suppression proof; deliberately carries no semantic revision."""

    id: UUID
    boundary: Boundary
    before: dict | None
    after: dict
    before_suppressed: bool
    after_suppressed: bool
    scheduled: bool = False
    new_logical_alert: bool = False


def replay_alert(
    state,
    current,
    transitions,
    *,
    now,
    change_order,
    budgets,
    active_contexts=None,
    context_boundaries=None,
    release_boundaries=None,
):
    """Repair one alert from complete ordered original proof, never current scans.

    The caller proves current suppression and canonical progress. Only after the
    entire field chain equals the current snapshot is its observed revision used.
    Current epoch/context/release barriers exclude every pre-reset transition.
    """
    rule = state.rule
    transitions = tuple(transitions)
    if not transitions or not transitions[0].new_logical_alert or transitions[0].before is not None:
        raise CorrelationProofError("correlation_replay_creation_proof_missing")
    previous = None
    previous_boundary = None
    for transition in transitions:
        if transition.boundary.at > now or (
            previous_boundary
            and (transition.boundary.at, transition.boundary.order) < previous_boundary
        ):
            raise CorrelationProofError("correlation_replay_order_invalid")
        if (
            transition.before != previous
            or (transition.before is None) != transition.new_logical_alert
        ):
            raise CorrelationProofError("correlation_replay_field_chain_broken")
        if str(transition.after.get("id")) != str(current.id) or str(
            transition.after.get("tenant_id")
        ) != str(rule.tenant_id):
            raise CorrelationProofError("correlation_replay_scope_invalid")
        previous = transition.after
        previous_boundary = (transition.boundary.at, transition.boundary.order)
    if previous != current.fields or current.tenant_id != rule.tenant_id:
        raise CorrelationProofError("correlation_replay_current_snapshot_unproven")
    others = tuple(m for m in state.memberships if m.alert_id != current.id and m.expiry > now)
    if not rule.enabled or rule.deleted or rule.health != "healthy":
        return replace(state, memberships=(), last_change_order=change_order)
    active_contexts = active_contexts or {}
    context_boundaries = context_boundaries or {}
    release_boundaries = release_boundaries or {}
    members = {}
    for transition in transitions:
        fields = transition.after
        group = group_key(rule.grouping, fields)
        context = context_for(rule, group) if group else None
        owner_ok = (
            current.active_incident_id is None
            or active_contexts.get(context) == current.active_incident_id
        )
        if (
            context is None
            or fields["status"] != "firing"
            or transition.after_suppressed
            or not owner_ok
        ):
            members = {}
            continue
        try:
            after_values = {
                c.id: c.program.evaluate(fields, transition.boundary.at) for c in rule.conditions
            }
            before_values = (
                {
                    c.id: c.program.evaluate(transition.before, transition.boundary.at)
                    for c in rule.conditions
                }
                if transition.before
                else {}
            )
            if any(
                type(value) is not bool
                for value in (*after_values.values(), *before_values.values())
            ):
                raise ValueError("nonboolean condition")
        except Exception:
            return EvidenceState(
                replace(rule, health="blocked"), (), change_order, "condition_evaluation_failed"
            )
        boundaries = [rule.epoch_boundary]
        if context in context_boundaries:
            boundaries.append(context_boundaries[context])
        if current.id in release_boundaries:
            boundaries.append(release_boundaries[current.id])
        allowed = all(
            transition.boundary.at > b.at
            if transition.scheduled
            else transition.boundary.order > b.order
            for b in boundaries
        )
        broad = (
            transition.new_logical_alert
            or transition.before_suppressed
            or transition.before["status"] == "resolved"
            or group_key(rule.grouping, transition.before) != group
        )
        updated = {}
        for condition in rule.conditions:
            if not after_values[condition.id]:
                continue
            prior = members.get(condition.id)
            if prior and prior.context == context and not broad:
                updated[condition.id] = prior
            elif allowed and (broad or not before_values.get(condition.id, False)):
                expiry = transition.boundary.at + timedelta(minutes=rule.window_minutes)
                if now < expiry:
                    updated[condition.id] = Membership(
                        context,
                        rule.epoch,
                        condition.id,
                        current.id,
                        transition.boundary.at,
                        expiry,
                        current.revision,
                        transition.id,
                    )
        members = updated
    if current.suppressed or current.status != "firing":
        members = {}
    result = others + tuple(members.values())
    if (
        len(result) > budgets.live_evidence
        or len({m.context for m in result}) > budgets.live_groups
    ):
        return EvidenceState(
            replace(rule, health="blocked"), (), change_order, "evidence_capacity_exceeded"
        )
    return replace(state, memberships=result, last_change_order=change_order)


@dataclass(frozen=True)
class EvidenceState:
    rule: Rule
    memberships: tuple[Membership, ...] = ()
    last_change_order: int = 0
    blocked_reason: str | None = None


@dataclass(frozen=True)
class Budgets:
    live_groups: int
    live_evidence: int

    def __post_init__(self):
        if self.live_groups < 1 or self.live_evidence < 1:
            raise ValueError("positive qualified evidence budgets required")


def edit_rule(
    state: EvidenceState,
    boundary: Boundary,
    *,
    conditions=None,
    grouping=None,
    window_minutes=None,
    enabled=None,
    delete=False,
) -> EvidenceState:
    old = state.rule
    if old.deleted:
        raise ValueError("deleted rules cannot be edited")
    conditions = old.conditions if conditions is None else tuple(conditions)
    grouping = old.grouping if grouping is None else tuple(grouping)
    window = old.window_minutes if window_minutes is None else window_minutes
    intent = old.enabled if enabled is None else enabled
    if delete:
        intent = False
    same_logic = {c.id: c.program.source for c in old.conditions} == {
        c.id: c.program.source for c in conditions
    }
    group_changed = grouping != old.grouping
    reset = (
        not same_logic
        or group_changed
        or window != old.window_minutes
        or intent != old.enabled
        or delete
    )
    metadata_equal = [(c.id, c.label, c.program.source) for c in conditions] == [
        (c.id, c.label, c.program.source) for c in old.conditions
    ]
    if metadata_equal and not reset:
        return state
    new = replace(
        old,
        conditions=conditions,
        grouping=grouping,
        window_minutes=window,
        enabled=intent,
        deleted=delete,
        revision=old.revision + 1,
        epoch=old.epoch + int(reset),
        grouping_generation=old.grouping_generation + int(group_changed),
        epoch_boundary=boundary if reset else old.epoch_boundary,
        health="healthy" if reset else old.health,
    )
    return EvidenceState(
        new,
        () if reset else state.memberships,
        state.last_change_order,
        None if reset else state.blocked_reason,
    )


def _after_boundaries(event: Input, boundaries: tuple[Boundary, ...]) -> bool:
    # Receive time is from ingress; PG order is only an application/proof cursor.
    # Equal-time control boundaries win, conservatively excluding the source.
    return all(event.qualifier.at > boundary.at for boundary in boundaries)


def _condition_values(rule: Rule, snapshot: Snapshot, at: datetime) -> dict[UUID, bool]:
    values = {}
    for condition in rule.conditions:
        result = condition.program.evaluate(snapshot.fields, at)
        if not isinstance(result, bool):
            raise ValueError("nonboolean condition")
        values[condition.id] = result
    return values


def _source_qualified_conditions(rule, event, group, release_boundary):
    """Reopened manual state needs a normal source transition per condition."""
    qualified = set()
    for before, after, at, released in event.source_provenance:
        allowed = release_boundary is None or at > release_boundary.at
        after_group = group_key(rule.grouping, after)
        if after["status"] != "firing" or after_group != group:
            qualified.clear()
            continue
        broad = released or before is None or before["status"] == "resolved" or group_key(rule.grouping, before) != group
        for condition in rule.conditions:
            after_value = condition.program.evaluate(after, at)
            before_value = condition.program.evaluate(before, at) if before is not None else False
            if type(after_value) is not bool or type(before_value) is not bool:
                raise ValueError("nonboolean source provenance condition")
            if not after_value:
                qualified.discard(condition.id)
            elif allowed and (broad or not before_value):
                qualified.add(condition.id)
    return qualified


def apply_input(
    state: EvidenceState,
    event: Input,
    *,
    now: datetime,
    budgets: Budgets,
    active_contexts: dict[Context, UUID] | None = None,
    context_boundaries: dict[Context, Boundary] | None = None,
    release_boundaries: dict[UUID, Boundary] | None = None,
) -> EvidenceState:
    _aware(now)
    rule = state.rule
    if (
        event.after.tenant_id != rule.tenant_id
        or event.change_order < 1
        or event.kind not in ("source", "manual", "scheduled", "bookkeeping")
    ):
        raise CorrelationProofError("invalid_correlation_scope_or_order")
    if event.change_order <= state.last_change_order:
        return state
    if (event.before is None) != event.new_logical_alert:
        raise CorrelationProofError("missing_prior_state_is_not_creation")
    derived = event.derived_qualifier
    if event.source_provenance is not None and not derived:
        raise CorrelationProofError("source_provenance_requires_derived_qualifier")
    if derived and (
        event.kind not in ("manual", "scheduled")
        or event.new_logical_alert
        or event.before is None
        or not event.before.suppressed
        or event.after.suppressed
        or event.before.fields != event.after.fields
        or event.before.status != "firing"
        or event.after.status != "firing"
        or event.before.revision != event.after.revision
    ):
        raise CorrelationProofError("invalid_derived_qualifier_proof")
    if event.before and (
        event.before.id != event.after.id
        or event.before.tenant_id != event.after.tenant_id
        or (event.before.revision >= event.after.revision and not derived)
    ):
        raise CorrelationProofError("invalid_prior_revision_proof")
    if event.qualifier.at > now:
        raise CorrelationProofError("database_clock_or_input_time_invalid")
    if not rule.enabled or rule.deleted or rule.health != "healthy":
        return replace(state, memberships=(), last_change_order=event.change_order)
    group = group_key(rule.grouping, event.after.fields)
    before_group = group_key(rule.grouping, event.before.fields) if event.before else None
    context = context_for(rule, group) if group is not None else None
    active_contexts, context_boundaries, release_boundaries = (
        active_contexts or {},
        context_boundaries or {},
        release_boundaries or {},
    )
    ownership_available = event.after.active_incident_id is None or (
        context is not None and active_contexts.get(context) == event.after.active_incident_id
    )
    current = [
        m
        for m in state.memberships
        if m.epoch == rule.epoch
        and m.context.grouping_generation == rule.grouping_generation
        and m.expiry > now
    ]
    eligible = (
        group is not None
        and event.after.status == "firing"
        and not event.after.suppressed
        and ownership_available
    )
    others = [m for m in current if m.alert_id != event.after.id]
    if not eligible:
        return replace(state, memberships=tuple(others), last_change_order=event.change_order)
    try:
        after_values = _condition_values(rule, event.after, event.qualifier.at)
        before_values = (
            _condition_values(rule, event.before, event.qualifier.at) if event.before else {}
        )
        source_qualified = None if event.source_provenance is None else _source_qualified_conditions(
            rule, event, group, release_boundaries.get(event.after.id)
        )
    except Exception:
        return EvidenceState(
            replace(rule, health="blocked"), (), event.change_order, "condition_evaluation_failed"
        )
    boundaries = [rule.epoch_boundary]
    if context in context_boundaries:
        boundaries.append(context_boundaries[context])
    if event.after.id in release_boundaries:
        boundaries.append(release_boundaries[event.after.id])
    can_start = event.kind in ("source", "scheduled") and _after_boundaries(event, tuple(boundaries))
    broad_transition = event.new_logical_alert or (
        event.before is not None
        and (event.before.status == "resolved" or event.before.suppressed or before_group != group)
    )
    existing = {
        m.condition_id: m for m in current if m.alert_id == event.after.id and m.context == context
    }
    for condition in rule.conditions:
        if not after_values[condition.id]:
            continue
        old = existing.get(condition.id)
        if old is not None and (not broad_transition or (derived and old.start > event.qualifier.at)):
            others.append(replace(old, observed_revision=event.after.revision))
        elif can_start and (source_qualified is None or condition.id in source_qualified) and (broad_transition or not before_values.get(condition.id, False)):
            try:
                expiry = event.qualifier.at + timedelta(minutes=rule.window_minutes)
            except OverflowError:
                raise CorrelationProofError("correlation_expiry_out_of_range") from None
            if event.qualifier.at <= now < expiry:
                others.append(
                    Membership(
                        context,
                        rule.epoch,
                        condition.id,
                        event.after.id,
                        event.qualifier.at,
                        expiry,
                        event.after.revision,
                        event.id,
                    )
                )
    if (
        len(others) > budgets.live_evidence
        or len({m.context for m in others}) > budgets.live_groups
    ):
        return EvidenceState(
            replace(rule, health="blocked"), (), event.change_order, "evidence_capacity_exceeded"
        )
    return EvidenceState(rule, tuple(others), event.change_order)


def clear_context(state: EvidenceState, context: Context) -> EvidenceState:
    """Persistence also records the resolution barrier in the same transaction."""
    return replace(state, memberships=tuple(m for m in state.memberships if m.context != context))


def release_alert(state: EvidenceState, alert_id: UUID) -> EvidenceState:
    """Persistence must retain release order/time; clearing alone is insufficient."""
    return replace(state, memberships=tuple(m for m in state.memberships if m.alert_id != alert_id))


def apply_all(
    states: tuple[EvidenceState, ...],
    event: Input,
    *,
    now: datetime,
    budgets: Budgets,
    tenant_evidence_budget: int,
    active_contexts=None,
    context_boundaries=None,
    release_boundaries=None,
) -> tuple[EvidenceState, ...]:
    """Apply one input to every rule in fixed order before any arbitration.

    Existing evidence in later rules still occupies capacity. An overflowing
    rule blocks and discards its own evidence; no unrelated match is evicted.
    """
    if tenant_evidence_budget < 1:
        raise ValueError("positive qualified tenant evidence budget required")
    if any(state.rule.tenant_id != event.after.tenant_id for state in states):
        raise CorrelationProofError("evidence_update_must_be_tenant_scoped")

    def live_size(state):
        return sum(
            1
            for m in state.memberships
            if m.epoch == state.rule.epoch
            and m.context.grouping_generation == state.rule.grouping_generation
            and m.start <= now < m.expiry
        )

    live = sum(live_size(state) for state in states)
    output = []
    for state in sorted(states, key=lambda s: (s.rule.created_at, s.rule.id.bytes)):
        live -= live_size(state)
        updated = apply_input(
            state,
            event,
            now=now,
            budgets=budgets,
            active_contexts=active_contexts,
            context_boundaries=context_boundaries,
            release_boundaries=release_boundaries,
        )
        if live + live_size(updated) > tenant_evidence_budget:
            updated = EvidenceState(
                replace(updated.rule, health="blocked"),
                (),
                updated.last_change_order,
                "tenant_evidence_capacity_exceeded",
            )
        live += live_size(updated)
        output.append(updated)
    return tuple(output)


@dataclass(frozen=True)
class Decision:
    context: Context
    rule_revision: int
    epoch: int
    decision_time: datetime
    existing_incident_id: UUID | None
    attachment_ids: tuple[UUID, ...]
    supports: tuple[Membership, ...]


def choose_decision(
    states: tuple[EvidenceState, ...],
    current_alerts: dict[UUID, Snapshot],
    *,
    now: datetime,
    active_contexts: dict[Context, UUID] | None = None,
    linked_alerts: dict[UUID, frozenset[UUID]] | None = None,
) -> Decision | None:
    """One complete winning operation, for fresh recheck and atomic DB commit.

    No manual 100-selection cap applies. If capacity cannot handle the complete
    decision, the persistence layer must block visibly, never truncate this set.
    Recompute subsequent winners from fresh state after each committed turn.
    """
    _aware(now)
    active_contexts, linked_alerts = active_contexts or {}, linked_alerts or {}
    tenants = {state.rule.tenant_id for state in states}
    if len(tenants) > 1:
        raise CorrelationProofError("decisions_must_be_tenant_scoped")
    for state in sorted(states, key=lambda s: (s.rule.created_at, s.rule.id.bytes)):
        rule = state.rule
        if not rule.enabled or rule.deleted or rule.health != "healthy":
            continue
        groups: dict[Context, list[Membership]] = {}
        for membership in state.memberships:
            context = membership.context
            alert = current_alerts.get(membership.alert_id)
            incident = active_contexts.get(context)
            if (
                membership.epoch != rule.epoch
                or context.rule_id != rule.id
                or context.tenant_id != rule.tenant_id
                or context.grouping_generation != rule.grouping_generation
                or not membership.start <= now < membership.expiry
                or alert is None
                or alert.tenant_id != rule.tenant_id
                or alert.revision != membership.observed_revision
                or alert.status != "firing"
                or alert.suppressed
                or group_key(rule.grouping, alert.fields) != context.group
                or (alert.active_incident_id is not None and alert.active_incident_id != incident)
            ):
                continue
            groups.setdefault(context, []).append(membership)
        for context in sorted(groups, key=lambda c: c.group.canonical):
            memberships = groups[context]
            target = active_contexts.get(context)
            condition_ids = {c.id for c in rule.conditions}
            satisfied = {m.condition_id for m in memberships}
            if target is None and not condition_ids.issubset(satisfied):
                continue
            if not condition_ids.intersection(satisfied):
                continue
            all_ids = {m.alert_id for m in memberships if m.condition_id in condition_ids}
            new_ids = all_ids - linked_alerts.get(target, frozenset()) if target else all_ids
            if not new_ids:
                continue
            return Decision(
                context,
                rule.revision,
                rule.epoch,
                now,
                target,
                tuple(sorted(new_ids, key=lambda value: value.bytes)),
                tuple(memberships),
            )
    return None
