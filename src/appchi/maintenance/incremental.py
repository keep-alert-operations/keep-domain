"""A bounded continuation for the source-release maintenance contract.

The immutable journal remains authoritative. Only strictly advancing receive
times after REV-34 use this path. A changed catalog, equal/backward receive time,
or legacy timer boundary asks for exact replay instead of guessing provenance.
"""

from dataclasses import asdict, replace
from datetime import datetime
from uuid import UUID

from appchi.serialization import wire

from .temporal import (
    Boundary,
    CauseInterval,
    EffectiveInterval,
    MaintenanceProofError,
    Reduction,
    _evaluate,
)


def checkpoint(result, last, *, generation, source_release_since, max_at=None):
    """Keep only live causes and the verified immediate predecessor."""
    return wire(
        {
            "version": 2,
            "generation": generation,
            "source_release_since": source_release_since,
            "last_order": last["original_order"],
            "last_at": last["effective_at"],
            "max_at": max_at or last["effective_at"],
            "snapshot": result.final_snapshot,
            "causes": [asdict(cause) for cause in result.causes if cause.closed is None],
        }
    )


def _boundary(value):
    return Boundary(datetime.fromisoformat(value["at"]), int(value["order"]), value["id"])


def _cause(value):
    return CauseInterval(
        UUID(value["id"]),
        value["cause_id"],
        UUID(value["window_id"]) if value["window_id"] else None,
        UUID(value["segment_id"]) if value["segment_id"] else None,
        _boundary(value["opened"]),
        None,
        datetime.fromisoformat(value["recorded_at"]),
    )


def advance(
    alert_id,
    continuation,
    intervals,
    transition,
    segments,
    *,
    now,
    generation,
    source_release_since,
    max_work,
):
    """Return a delta Reduction and next continuation, or None for exact replay.

    Because the receive time strictly advances, a finished historical interval
    cannot be changed or acquire different qualifier provenance. A final release
    is the current explicit input, never a reconstructed timer or source repeat.
    """
    if (
        not continuation
        or continuation.get("version") not in (1, "1", 2, "2")
        or source_release_since is None
    ):
        return None
    boundary = transition.boundary
    if (
        int(continuation["generation"]) != generation
        or continuation["source_release_since"] != wire(source_release_since)
        or boundary.at
        <= datetime.fromisoformat(continuation.get("max_at", continuation["last_at"]))
        or boundary.at < source_release_since
    ):
        return None
    if (
        boundary.order <= int(continuation["last_order"])
        or transition.before != continuation["snapshot"]
    ):
        raise MaintenanceProofError("missing_immediate_predecessor_proof")
    if transition.new_logical_alert or boundary.at > now:
        raise MaintenanceProofError("maintenance_incremental_boundary_invalid")
    if transition.after.get("status") not in ("firing", "resolved"):
        raise MaintenanceProofError("invalid_rule_field_snapshot")
    active = {value["cause_id"]: _cause(value) for value in continuation["causes"]}
    relevant = [
        segment for segment in segments if str(segment.id) in active or segment.covers(boundary)
    ]
    # This is an input-work bound, not a lifetime-history bound.
    if 2 * len(relevant) + 1 > max_work:
        raise MaintenanceProofError("maintenance_work_allocation_exceeded")
    deltas = {}

    def close(cause_id):
        previous = active.pop(cause_id, None)
        if previous is not None:
            deltas[previous.id] = replace(previous, closed=boundary)

    def open_cause(cause_id, segment=None):
        from uuid import uuid5

        if cause_id not in active:
            cause = CauseInterval(
                uuid5(alert_id, cause_id + ":" + boundary.id),
                cause_id,
                segment.window_id if segment else None,
                segment.id if segment else None,
                boundary,
                None,
                now,
            )
            active[cause_id] = cause
            deltas[cause.id] = cause

    before, after = transition.before, transition.after
    was_suppressed = bool(active)
    for segment in relevant:
        end, _ = segment.termination
        if end.at <= boundary.at:
            if end.at < source_release_since:
                return None
            if transition.kind == "source":
                close(str(segment.id))
        if not segment.covers(boundary):
            continue
        after_match = _evaluate(segment, after, boundary.at)
        before_match = _evaluate(segment, before, boundary.at)
        if not after_match:
            close(str(segment.id))
        elif (before["status"] == "resolved" and after["status"] == "firing") or (
            not before_match and after["status"] == "firing"
        ):
            open_cause(str(segment.id), segment)
    if transition.source_suppressed is not None:
        if after.get("schema_version") != "v2" and transition.source_suppressed:
            raise MaintenanceProofError("v1_source_suppression_forbidden")
        if transition.source_suppressed and after["status"] != "firing":
            raise MaintenanceProofError("resolved_source_suppression_invalid")
        if transition.source_suppressed:
            open_cause("source:v2")
        else:
            close("source:v2")
    union = [
        EffectiveInterval(
            datetime.fromisoformat(item["start"]),
            datetime.fromisoformat(item["end"]) if item["end"] else None,
        )
        for item in intervals[-1:]
    ]
    qualifiers = ()
    proofs = ()
    if active and not was_suppressed:
        union = [EffectiveInterval(boundary.at, None)]
    elif was_suppressed and not active:
        if not union or union[-1].end is not None:
            raise MaintenanceProofError("maintenance_incremental_union_unproven")
        union[-1] = replace(union[-1], end=boundary.at)
        if after["status"] == "firing":
            qualifiers = (boundary.at,)
            source = transition.kind == "source"
            proofs = ((boundary.at, boundary.id, source, boundary.id if source else None),)
    result = Reduction(
        tuple(deltas.values()),
        tuple(union),
        tuple(sorted(active)),
        qualifiers,
        frozenset(),
        after,
        proofs,
    )
    next_state = wire(
        {
            **continuation,
            "version": 2,
            "last_order": boundary.order,
            "last_at": boundary.at,
            "max_at": boundary.at,
            "snapshot": after,
            "causes": [asdict(cause) for cause in active.values()],
        }
    )
    return result, next_state
