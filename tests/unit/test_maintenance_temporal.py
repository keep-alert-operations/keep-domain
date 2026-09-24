from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from appchi.maintenance.temporal import (
    AlertTransition,
    Boundary,
    MaintenanceConflict,
    MaintenanceProofError,
    Segment,
    WindowState,
    change_window,
    reduce_alert,
    revise_segments,
)

BASE = datetime(2026, 9, 22, 10, tzinfo=UTC)


def at(minutes):
    return BASE + timedelta(minutes=minutes)


def boundary(minutes, order=1, name=None):
    return Boundary(at(minutes), order, name or f"event-{minutes}-{order}")


class Program:
    """Reducer-only double. Compiler correctness is established by CEL tests."""

    def evaluate(self, alert, evaluated_at):
        return alert["message"] == "match"


def segment(start=0, end=60, activation=-10, order=1):
    return Segment(uuid4(), uuid4(), 1, boundary(activation, order), at(start), at(end), Program())


def snapshot(message="match", status="firing", version="v1"):
    return {"message": message, "status": status, "schema_version": version}


def transition(minutes, before, after, *, order=1, source=None):
    return AlertTransition(boundary(minutes, order), before, after, before is None, source)


def reduce(segments, events, now=70):
    return reduce_alert(
        uuid4(),
        tuple(segments),
        tuple(events),
        now=at(now),
        recorded_at=at(now),
        proof_complete=True,
    )


def test_delayed_creation_records_original_interval_and_end_qualifier_only():
    result = reduce([segment()], [transition(10, None, snapshot())])
    assert result.causes[0].opened.at == at(10)
    assert result.causes[0].closed.at == at(60)
    assert result.causes[0].recorded_at == at(70)
    assert result.current_causes == ()
    assert result.final_unsuppression_qualifiers == (at(60),)


def test_no_backfill_on_create_enable_or_true_repeat():
    s = segment(activation=5)
    state = snapshot()
    result = reduce([s], [transition(0, None, state), transition(10, state, state)])
    assert result.causes == ()
    assert result.final_unsuppression_qualifiers == ()


def test_before_create_same_time_order_is_excluded_after_is_eligible():
    s = segment(activation=0, order=3)
    assert reduce([s], [transition(0, None, snapshot(), order=2)]).causes == ()
    assert len(reduce([s], [transition(0, None, snapshot(), order=4)]).causes) == 1


def test_half_open_end_and_scheduled_start_boundaries():
    s = segment()
    assert len(reduce([s], [transition(0, None, snapshot())]).causes) == 1
    assert reduce([s], [transition(60, None, snapshot())]).causes == ()


def test_overlap_and_source_union_produce_one_final_release():
    state = snapshot(version="v2")
    result = reduce(
        [segment(end=30), segment(end=40)],
        [transition(10, None, state, source=True), transition(50, state, state, source=False)],
    )
    assert len(result.causes) == 3
    assert len(result.effective_intervals) == 1
    assert result.effective_intervals[0].start == at(10)
    assert result.effective_intervals[0].end == at(50)
    assert result.final_unsuppression_qualifiers == (at(50),)


def test_resolution_retains_matching_cause_but_resolved_mismatch_closes():
    firing, resolved, mismatch = (
        snapshot(),
        snapshot(status="resolved"),
        snapshot("different", "resolved"),
    )
    result = reduce(
        [segment()],
        [
            transition(10, None, firing),
            transition(20, firing, resolved),
            transition(30, resolved, mismatch),
        ],
    )
    assert result.causes[0].closed.at == at(30)
    assert result.final_unsuppression_qualifiers == ()


def test_first_seen_resolved_can_have_history_without_correlation_qualifier():
    result = reduce([segment()], [transition(10, None, snapshot(status="resolved"))])
    assert len(result.causes) == 1
    assert result.final_unsuppression_qualifiers == ()


def test_false_to_true_firing_and_refiring_open_but_resolved_match_does_not():
    missing, matching = snapshot("different"), snapshot()
    result = reduce([segment()], [transition(0, None, missing), transition(10, missing, matching)])
    assert result.causes[0].opened.at == at(10)
    before, after = snapshot("different", "resolved"), snapshot("match", "resolved")
    result = reduce(
        [segment()],
        [
            transition(0, None, before),
            transition(10, before, after),
            transition(20, after, matching),
        ],
    )
    assert result.causes[0].opened.at == at(20)


def test_disable_enable_retains_history_and_never_reopens_without_transition():
    old = replace(segment(), deactivation=boundary(20))
    new = segment(activation=30)
    state = snapshot()
    result = reduce([old, new], [transition(10, None, state), transition(40, state, state)])
    assert len(result.causes) == 1 and result.causes[0].closed.at == at(20)
    assert result.current_causes == ()


def test_same_time_close_open_coalesces_union_without_extra_qualifier():
    s = segment()
    yes, no = snapshot(), snapshot("different")
    result = reduce(
        [s],
        [
            transition(10, None, yes),
            transition(20, yes, no, order=1),
            transition(20, no, yes, order=2),
        ],
    )
    assert len(result.causes) == 2
    assert len(result.effective_intervals) == 1
    assert result.final_unsuppression_qualifiers == (at(60),)


def test_replay_has_stable_interval_ids_and_unique_transition_keys():
    aid, s = uuid4(), segment()
    event = transition(10, None, snapshot())
    arguments = dict(now=at(70), recorded_at=at(70), proof_complete=True)
    one = reduce_alert(aid, (s,), (event,), **arguments)
    two = reduce_alert(aid, (s,), (event, event), **arguments)
    assert one == two
    assert len(one.transition_keys) == 2


def test_missing_predecessor_unknown_proof_and_cel_failure_block():
    s = segment()
    with pytest.raises(MaintenanceProofError):
        reduce(
            [s],
            [
                transition(0, None, snapshot()),
                transition(1, snapshot("invented-before"), snapshot()),
            ],
        )
    with pytest.raises(MaintenanceProofError):
        reduce_alert(
            uuid4(),
            (s,),
            (transition(0, None, snapshot()),),
            now=at(70),
            recorded_at=at(70),
            proof_complete=False,
        )

    class Broken:
        def evaluate(self, *args):
            raise RuntimeError("engine failed")

    with pytest.raises(MaintenanceProofError):
        reduce([replace(s, program=Broken())], [transition(0, None, snapshot())])


def test_irreversible_start_lock_and_expiry_checked_against_action_time():
    state = WindowState(at(10), at(60), "expression-v1", enabled=False)
    locked = change_window(state, action_time=at(10))
    assert locked.started_lock and locked.revision == state.revision
    with pytest.raises(MaintenanceConflict) as error:
        change_window(locked, action_time=at(11), start=at(20))
    assert error.value.code == "maintenance_start_locked"
    with pytest.raises(MaintenanceConflict):
        change_window(state, action_time=at(60), end=at(80))
    with pytest.raises(MaintenanceConflict):
        change_window(state, action_time=at(60), enabled=True)
    extended = change_window(state, action_time=at(59), end=at(80))
    assert extended.end == at(80) and extended.started_lock


def test_moving_start_into_past_locks_immediately_and_noop_keeps_revision():
    state = WindowState(at(10), at(60), "expression-v1")
    updated = change_window(state, action_time=at(5), start=at(0))
    assert updated.started_lock and updated.revision == 2
    assert (
        change_window(updated, action_time=at(6), start=at(0), cel_digest="expression-v1").revision
        == 2
    )


def test_end_extension_preserves_segment_activation_and_historical_end_proof():
    window_id = uuid4()
    initial = WindowState(at(0), at(30), "same-expression")
    timeline = revise_segments(window_id, None, initial, (), boundary(-10), Program())
    updated = change_window(initial, action_time=at(20), end=at(60))
    extended = revise_segments(window_id, initial, updated, timeline, boundary(20), Program())
    assert len(extended) == 1
    assert extended[0].id == timeline[0].id
    assert extended[0].activation == timeline[0].activation
    assert [end for _, end in extended[0].end_revisions] == [at(30), at(60)]
    result = reduce(extended, [transition(10, None, snapshot())])
    assert result.causes[0].closed.at == at(60)


def test_reenable_creates_new_segment_and_retains_closed_old_segment():
    window_id = uuid4()
    initial = WindowState(at(0), at(60), "same-expression")
    timeline = revise_segments(window_id, None, initial, (), boundary(-10), Program())
    disabled = change_window(initial, action_time=at(10), enabled=False)
    timeline = revise_segments(window_id, initial, disabled, timeline, boundary(10), Program())
    enabled = change_window(disabled, action_time=at(20), enabled=True)
    timeline = revise_segments(window_id, disabled, enabled, timeline, boundary(20), Program())
    assert len(timeline) == 2
    assert timeline[0].deactivation.at == at(10)
    assert timeline[1].activation.at == at(20)
    state = snapshot()
    assert (
        len(reduce(timeline, [transition(5, None, state), transition(25, state, state)]).causes)
        == 1
    )


def test_reducer_runs_the_shared_native_cel_program():
    from appchi.cel import compile_expression

    compiled = compile_expression('alert.message == "match"', rule=True)
    s = replace(segment(), program=compiled)
    assert len(reduce([s], [transition(10, None, snapshot())]).causes) == 1
