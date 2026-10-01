"""Pure one-alert temporal reduction from complete authoritative proof.

This module never scans existing alerts on activation. Persistence supplies a
complete retained timeline and journal; it commits returned effects atomically.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid5


class MaintenanceProofError(RuntimeError):
    """Retain affected admitted work; unknown proof never means unsuppressed."""


class MaintenanceConflict(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _aware(at: datetime):
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("authoritative aware instants are required")


@dataclass(frozen=True, order=True)
class Boundary:
    at: datetime
    order: int
    id: str

    def __post_init__(self):
        _aware(self.at)
        if self.order < 0 or not self.id:
            raise ValueError("invalid boundary proof")


class RuleProgram(Protocol):
    def evaluate(self, alert: dict, evaluated_at: datetime) -> bool: ...


@dataclass(frozen=True)
class Segment:
    id: UUID
    window_id: UUID
    expression_revision: int
    activation: Boundary
    start: datetime
    end: datetime
    program: RuleProgram
    deactivation: Boundary | None = None
    end_revisions: tuple[tuple[Boundary, datetime], ...] = ()

    def __post_init__(self):
        _aware(self.start)
        _aware(self.end)
        if self.end <= self.start or self.expression_revision < 1:
            raise ValueError("invalid maintenance segment")
        if self.deactivation and (self.deactivation.at, self.deactivation.order) < (
            self.activation.at,
            self.activation.order,
        ):
            raise ValueError("segment deactivation precedes activation")

    def covers(self, boundary: Boundary) -> bool:
        return (
            self.start <= boundary.at < self.end
            and boundary.at > self.activation.at
            and (self.deactivation is None or boundary.at < self.deactivation.at)
        )

    @property
    def termination(self) -> tuple[Boundary, bool]:
        if self.deactivation is not None and self.deactivation.at < self.end:
            return self.deactivation, False
        # Scheduled ends sort before all source/control events at the same time.
        return Boundary(self.end, 0, f"end:{self.id}:{self.end.isoformat()}"), True


@dataclass(frozen=True)
class WindowState:
    start: datetime
    end: datetime
    cel_digest: str
    enabled: bool = True
    started_lock: bool = False
    deleted: bool = False
    revision: int = 1

    def __post_init__(self):
        _aware(self.start)
        _aware(self.end)
        if self.end <= self.start:
            raise ValueError("invalid maintenance schedule")

    def phase(self, now: datetime) -> str:
        if self.deleted:
            return "deleted"
        return "ended" if now >= self.end else "active" if now >= self.start else "scheduled"


def change_window(
    state: WindowState,
    *,
    action_time: datetime,
    start: datetime | None = None,
    end: datetime | None = None,
    cel_digest: str | None = None,
    enabled: bool | None = None,
    delete: bool = False,
) -> WindowState:
    """Call after acquiring coordinator/window locks with fresh database time.

    Timezone-only/metadata-only changes do not pass start/end values here. The
    persistence layer owns metadata revisions and immutable control snapshots.
    """
    _aware(action_time)
    if state.deleted:
        raise MaintenanceConflict("maintenance_deleted")
    locked = state.started_lock or action_time >= state.start
    if locked and (
        (start is not None and start != state.start)
        or (cel_digest is not None and cel_digest != state.cel_digest)
    ):
        raise MaintenanceConflict("maintenance_start_locked")
    if action_time >= state.end and ((end is not None and end != state.end) or enabled is True):
        raise MaintenanceConflict("maintenance_ended")
    new_start, new_end = start or state.start, end or state.end
    if new_end <= new_start or (
        end is not None and new_end != state.end and new_end <= action_time
    ):
        raise MaintenanceConflict("invalid_maintenance_end")
    new = replace(
        state,
        start=new_start,
        end=new_end,
        cel_digest=cel_digest if cel_digest is not None else state.cel_digest,
        enabled=enabled if enabled is not None else state.enabled,
        deleted=delete,
        started_lock=locked or action_time >= new_start,
    )
    # Reaching the irreversible time lock is not a synthetic user revision.
    old_content = replace(state, started_lock=new.started_lock)
    return replace(new, revision=state.revision + int(new != old_content))


def revise_segments(
    window_id: UUID,
    previous: WindowState | None,
    current: WindowState,
    segments: tuple[Segment, ...],
    boundary: Boundary,
    program: RuleProgram,
) -> tuple[Segment, ...]:
    """Derive immutable segment history after a validated window command.

    End extension/shortening updates the current segment with retained end proof;
    enabling or changing a not-yet-started expression/schedule starts a fresh
    activation. This function never receives or evaluates existing alerts.
    """
    result = list(segments)
    live = [
        i
        for i, segment in enumerate(result)
        if segment.deactivation is None and segment.end > boundary.at
    ]
    if len(live) > 1 or any(s.window_id != window_id for s in segments):
        raise MaintenanceProofError("invalid_window_segment_history")
    if previous == current:
        return segments
    replacement = (
        previous is None
        or previous.start != current.start
        or previous.cel_digest != current.cel_digest
    )
    stop = current.deleted or not current.enabled or replacement
    if live and stop:
        index = live[0]
        result[index] = replace(result[index], deactivation=boundary)
    if live and not stop and result[live[0]].end != current.end:
        index = live[0]
        result[index] = replace(
            result[index],
            end=current.end,
            end_revisions=result[index].end_revisions + ((boundary, current.end),),
        )
    newly_enabled = previous is not None and not previous.enabled and current.enabled
    if (
        current.enabled
        and not current.deleted
        and boundary.at < current.end
        and (replacement or newly_enabled)
    ):
        segment_id = uuid5(window_id, "segment:" + boundary.id)
        if any(s.id == segment_id for s in result):
            raise MaintenanceProofError("conflicting_segment_activation_replay")
        result.append(
            Segment(
                segment_id,
                window_id,
                current.revision,
                boundary,
                current.start,
                current.end,
                program,
                end_revisions=((boundary, current.end),),
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class AlertTransition:
    boundary: Boundary
    before: dict | None
    after: dict
    new_logical_alert: bool = False
    source_suppressed: bool | None = None
    kind: str = "source"


@dataclass(frozen=True)
class CauseInterval:
    id: UUID
    cause_id: str
    window_id: UUID | None
    segment_id: UUID | None
    opened: Boundary
    closed: Boundary | None
    recorded_at: datetime


@dataclass(frozen=True)
class EffectiveInterval:
    start: datetime
    end: datetime | None


@dataclass(frozen=True)
class Reduction:
    causes: tuple[CauseInterval, ...]
    effective_intervals: tuple[EffectiveInterval, ...]
    current_causes: tuple[str, ...]
    final_unsuppression_qualifiers: tuple[datetime, ...]
    transition_keys: frozenset[tuple[str, str, str, str]]
    final_snapshot: dict | None
    qualifier_inputs: tuple[tuple[datetime, str, bool, str | None], ...] = ()


def _evaluate(segment: Segment, snapshot: dict, at: datetime) -> bool:
    try:
        result = segment.program.evaluate(snapshot, at)
    except Exception:
        raise MaintenanceProofError("maintenance_condition_evaluation_failed") from None
    if not isinstance(result, bool):
        raise MaintenanceProofError("maintenance_condition_result_invalid")
    return result


def reduce_alert(
    alert_id: UUID,
    segments: tuple[Segment, ...],
    transitions: tuple[AlertTransition, ...],
    *,
    now: datetime,
    recorded_at: datetime,
    proof_complete: bool,
    max_work: int = 10000,
    source_release_since: datetime | None = None,
) -> Reduction:
    """Rebuild retained cause proof without mutating a newer materialized alert.

    Inputs must include the new-alert baseline and all subsequent relevant
    transitions, including source-cause changes. Missing proof blocks; callers
    needing incremental reduction must retain an equivalent verified checkpoint.
    """
    _aware(now)
    _aware(recorded_at)
    if not proof_complete or not transitions:
        raise MaintenanceProofError("maintenance_complete_timeline_required")
    if len(segments) * len(transitions) + len(segments) + len(transitions) > max_work:
        raise MaintenanceProofError("maintenance_work_allocation_exceeded")
    if len({segment.id for segment in segments}) != len(segments):
        raise MaintenanceProofError("duplicate_maintenance_segment")
    unique = {}
    for transition in transitions:
        old = unique.get(transition.boundary.id)
        if old is not None and old != transition:
            raise MaintenanceProofError("conflicting_transition_replay")
        unique[transition.boundary.id] = transition
    # Application order proves the before/after chain. UTC determines coverage,
    # but cannot sort state mutations across concurrent ingress clocks/manual writes.
    ordered = sorted(unique.values(), key=lambda t: t.boundary.order)
    if len({(t.boundary.at, t.boundary.order) for t in ordered}) != len(ordered):
        raise MaintenanceProofError("ambiguous_transition_order")
    if any(t.boundary.at > now for t in ordered):
        raise MaintenanceProofError("maintenance_future_receive_time")
    active: dict[str, int] = {}
    causes: list[CauseInterval] = []
    keys = set()
    snapshot = None
    status_history: list[AlertTransition] = []
    source_qualifiers: dict[str, Boundary] = {}

    def close(cause_id: str, boundary: Boundary):
        index = active.pop(cause_id, None)
        if index is not None:
            # An older receive clock cannot create a negative interval when its
            # source mutation is applied after a newer manual/source mutation.
            closed = (
                boundary
                if boundary.at >= causes[index].opened.at
                else replace(boundary, at=causes[index].opened.at)
            )
            causes[index] = replace(causes[index], closed=closed)
            keys.add((str(alert_id), cause_id, "close", boundary.id))

    def open_cause(cause_id: str, boundary: Boundary, segment: Segment | None):
        if cause_id in active:
            return
        interval_id = uuid5(alert_id, cause_id + ":" + boundary.id)
        active[cause_id] = len(causes)
        causes.append(
            CauseInterval(
                interval_id,
                cause_id,
                segment.window_id if segment else None,
                segment.id if segment else None,
                boundary,
                None,
                recorded_at,
            )
        )
        keys.add((str(alert_id), cause_id, "open", boundary.id))

    for transition in ordered:
        boundary = transition.boundary
        for segment in segments:
            end, _ = segment.termination
            if end.at <= boundary.at:
                if source_release_since is None or end.at < source_release_since:
                    close(str(segment.id), end)
                elif transition.kind == "source":
                    close(str(segment.id), boundary)
        if transition.after.get("status") not in ("firing", "resolved"):
            raise MaintenanceProofError("invalid_rule_field_snapshot")
        if snapshot is None:
            if not transition.new_logical_alert or transition.before is not None:
                raise MaintenanceProofError("missing_new_alert_baseline")
        elif (
            transition.new_logical_alert
            or transition.before is None
            or transition.before != snapshot
        ):
            raise MaintenanceProofError("missing_immediate_predecessor_proof")
        before, after = transition.before, transition.after
        for segment in segments:
            cause_id = str(segment.id)
            if not segment.covers(boundary):
                continue
            after_match = _evaluate(segment, after, boundary.at)
            before_match = False if before is None else _evaluate(segment, before, boundary.at)
            if not after_match:
                close(cause_id, boundary)
            elif (
                transition.new_logical_alert
                or (
                    before is not None
                    and before.get("status") == "resolved"
                    and after["status"] == "firing"
                )
                or (before is not None and not before_match and after["status"] == "firing")
            ):
                open_cause(cause_id, boundary, segment)
                if transition.kind == "source":
                    # A source refire can qualify while a matching maintenance
                    # cause survives a manual resolve. Its provenance must not
                    # remain pinned to the older cause-opening receipt.
                    source_qualifiers[boundary.id] = boundary
        if transition.source_suppressed is not None:
            if after.get("schema_version") != "v2" and transition.source_suppressed:
                raise MaintenanceProofError("v1_source_suppression_forbidden")
            if transition.source_suppressed and after["status"] != "firing":
                raise MaintenanceProofError("resolved_source_suppression_invalid")
            if transition.source_suppressed:
                open_cause("source:v2", boundary, None)
            else:
                close("source:v2", boundary)
        snapshot = after
        status_history.append(transition)
    for segment in segments:
        end, _ = segment.termination
        if end.at <= now and (source_release_since is None or end.at < source_release_since):
            close(str(segment.id), end)
    if snapshot is None:
        raise MaintenanceProofError("missing_current_alert_baseline")
    intervals = []
    # Merge all causes by wall-clock effective intervals, coalescing equal-time
    # close/reopen and zero-duration intervals without a fictitious visual blink.
    for cause in sorted(causes, key=lambda c: c.opened.at):
        end = cause.closed.at if cause.closed else None
        if end is not None and end <= cause.opened.at:
            continue
        if intervals and (intervals[-1].end is None or cause.opened.at <= intervals[-1].end):
            previous = intervals[-1]
            combined_end = None if previous.end is None or end is None else max(previous.end, end)
            intervals[-1] = EffectiveInterval(previous.start, combined_end)
        else:
            intervals.append(EffectiveInterval(cause.opened.at, end))
    qualifiers = []
    qualifier_inputs = []
    for interval in intervals:
        if interval.end is None:
            continue
        # Scheduled end precedes sources at that exact instant; use original
        # status immediately before end. Control/source closes use own order.
        closes = [c.closed for c in causes if c.closed and c.closed.at == interval.end]
        end_boundary = max(closes, key=lambda b: b.order)
        eligible_inputs = [
            t
            for t in status_history
            if (t.boundary.at, t.boundary.order) <= (end_boundary.at, end_boundary.order)
        ]
        current_input = eligible_inputs[-1] if eligible_inputs else None
        if current_input and current_input.after["status"] == "firing":
            qualifiers.append(interval.end)
            manual_reset = max(
                (
                    t.boundary.order
                    for t in eligible_inputs
                    if t.kind != "source" and t.before and t.before["status"] != t.after["status"]
                ),
                default=0,
            )
            origins = {t.boundary.id: t for t in eligible_inputs}
            source_origins = [
                c.opened
                for c in causes
                if (
                    c.opened.id in origins
                    and origins[c.opened.id].kind == "source"
                    and c.opened.order > manual_reset
                    and c.opened.at < interval.end
                    and (c.closed is None or c.closed.at > interval.start)
                )
            ]
            source_origins.extend(
                b
                for b in source_qualifiers.values()
                if b.id in origins
                and b.order > manual_reset
                and interval.start <= b.at < interval.end
            )
            if manual_reset:
                # Per-rule normal source qualification is checked downstream
                # from this retained post-reset chain. A mere repeat contributes
                # no eligibility, even though it is valid source provenance.
                source_origins.extend(
                    t.boundary
                    for t in eligible_inputs
                    if t.kind == "source"
                    and t.boundary.order > manual_reset
                    and t.after["status"] == "firing"
                    and interval.start <= t.boundary.at < interval.end
                )
            # A direct source release is itself a qualifying source transition.
            source_release = (
                end_boundary.id in origins and origins[end_boundary.id].kind == "source"
            )
            manual_release = (
                end_boundary.id in origins and origins[end_boundary.id].kind != "source"
            )
            origin = (
                None
                if manual_release
                else end_boundary
                if source_release
                else max(source_origins, key=lambda b: b.order, default=None)
            )
            qualifier_inputs.append(
                (
                    interval.end,
                    current_input.boundary.id,
                    origin is not None,
                    origin.id if origin else None,
                )
            )
    return Reduction(
        tuple(causes),
        tuple(intervals),
        tuple(sorted(active)),
        tuple(qualifiers),
        frozenset(keys),
        snapshot,
        tuple(qualifier_inputs),
    )
