from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from keep.alerts.dismissal import (
    correlation_suppressed,
    dismissal_active,
    dismissal_reason,
    dismissal_view,
    effective_suppressed,
)
from keep.alerts.lifecycle import apply_command, apply_source
from keep.cel import compile_expression
from keep.search.projection import Projection, build_document
from keep.shared.errors import AppError

NOW = datetime(2026, 10, 28, 12, 30, tzinfo=UTC)
ACTOR = uuid4()


def source_item(payload, when, version="v1"):
    return {
        "payload": payload,
        "received_at": when,
        "version": version,
        "tenant_id": uuid4(),
        "id": uuid4(),
        "key_field": "test",
    }


@pytest.fixture
def firing(v1):
    current, _ = apply_source(None, source_item(v1, NOW - timedelta(hours=1)))
    current.update(dismissed_until=None, dismissed_at=None, dismissed_by=None)
    return current


def dismiss(row, value, when=NOW):
    return apply_command(row, "set_dismissal", value, ACTOR, when)


def test_duration_is_measured_from_the_server_clock(firing):
    """Requirements: REV-49; alert operations 29."""
    dismissed, changed = dismiss(firing, {"duration_seconds": 7200, "reason": None})
    assert changed and dismissed["revision"] == firing["revision"] + 1
    assert dismissed["dismissed_until"] == NOW + timedelta(hours=2)
    assert dismissed["dismissed_at"] == NOW and dismissed["dismissed_by"] == ACTOR
    assert dismissed["suppressed"] is False  # stored causes are unchanged
    assert dismissed["status"] == "firing" and dismissed["assignee_id"] is None


def test_until_form_and_bounds(firing):
    """Requirements: REV-49; alert operations 29."""
    until = (NOW + timedelta(days=30)).isoformat()
    dismissed, _ = dismiss(firing, {"until": until})
    assert dismissed["dismissed_until"] == NOW + timedelta(days=30)
    for value, code in (
        ({"until": NOW.isoformat()}, "dismissal_end_passed"),
        ({"until": (NOW - timedelta(minutes=1)).isoformat()}, "dismissal_end_passed"),
        ({"until": (NOW + timedelta(days=30, seconds=1)).isoformat()}, "dismissal_too_long"),
        ({"duration_seconds": 30 * 86400 + 1}, "dismissal_too_long"),
    ):
        with pytest.raises(AppError) as error:
            dismiss(firing, value)
        assert error.value.code == code and error.value.status == 422


def test_only_firing_alerts_can_be_dismissed(firing):
    """Requirements: REV-49; alert operations 29."""
    resolved, _ = apply_command(firing, "set_status", "resolved", ACTOR, NOW)
    with pytest.raises(AppError) as error:
        dismiss(resolved, {"duration_seconds": 60})
    assert error.value.code == "alert_not_firing"
    # Ending an absent dismissal is a no-op in any state.
    unchanged, changed = dismiss(resolved, None)
    assert not changed and unchanged["revision"] == resolved["revision"]


def test_change_same_end_and_undismiss(firing):
    """Requirements: REV-49; alert operations 29."""
    dismissed, _ = dismiss(firing, {"duration_seconds": 3600})
    same, changed = apply_command(
        dismissed, "set_dismissal", {"until": (NOW + timedelta(hours=1)).isoformat()}, uuid4(), NOW
    )
    assert not changed and same["dismissed_by"] == ACTOR
    later, changed = dismiss(dismissed, {"duration_seconds": 7200}, NOW + timedelta(minutes=5))
    assert changed and later["dismissed_until"] == NOW + timedelta(hours=2, minutes=5)
    ended, changed = dismiss(later, None, NOW + timedelta(minutes=6))
    assert changed and ended["dismissed_until"] is None and ended["dismissed_by"] is None


def test_resolution_keeps_and_new_occurrence_ends_a_dismissal(firing, v1):
    """Requirements: REV-49; alert operations 29."""
    dismissed, _ = dismiss(firing, {"duration_seconds": 3600})
    resolved, _ = apply_command(dismissed, "set_status", "resolved", ACTOR, NOW)
    assert resolved["dismissed_until"] == dismissed["dismissed_until"]
    reopened, _ = apply_command(resolved, "set_status", "firing", ACTOR, NOW)
    assert reopened["occurrence_number"] == firing["occurrence_number"] + 1
    assert reopened["dismissed_until"] is None
    original = v1["severity"]
    v1["severity"] = "clear"
    cleared, _ = apply_source(dismissed, source_item(v1, NOW + timedelta(minutes=1)))
    assert cleared["status"] == "resolved" and cleared["dismissed_until"] is not None
    v1["severity"] = original
    refired, changed = apply_source(cleared, source_item(v1, NOW + timedelta(minutes=2)))
    assert changed and refired["dismissed_until"] is None


def test_first_source_input_at_the_end_clears_it(firing, v1):
    """Requirements: REV-49; alert operations 29."""
    dismissed, _ = dismiss(firing, {"duration_seconds": 3600})
    end = NOW + timedelta(hours=1)
    repeat, changed = apply_source(dismissed, source_item(v1, end - timedelta(microseconds=1)))
    assert not changed and repeat["dismissed_until"] == end
    after, changed = apply_source(repeat, source_item(v1, end))
    assert changed and after["dismissed_until"] is None
    assert after["revision"] == repeat["revision"] + 1


def test_a_command_after_the_end_records_the_end(firing):
    """Requirements: REV-49; alert operations 29."""
    dismissed, _ = dismiss(firing, {"duration_seconds": 60})
    assigned, changed = apply_command(
        dismissed, "set_assignee", str(ACTOR), ACTOR, NOW + timedelta(minutes=2)
    )
    assert changed and assigned["dismissed_until"] is None
    assert str(assigned["assignee_id"]) == str(ACTOR)


def test_effective_and_correlation_suppression(firing):
    """Requirements: REV-49; alert operations 29."""
    dismissed, _ = dismiss(firing, {"duration_seconds": 3600})
    end = dismissed["dismissed_until"]
    assert effective_suppressed(dismissed, end - timedelta(microseconds=1))
    assert not effective_suppressed(dismissed, end)
    assert not dismissal_active(firing, NOW) and not effective_suppressed(firing, NOW)
    # Correlation holds a recorded dismissal until a write clears it.
    assert correlation_suppressed(dismissed) and not correlation_suppressed(firing)
    assert dismissal_view(dismissed, NOW)["state"] == "active"
    assert dismissal_view(dismissed, end)["state"] == "expired"
    assert dismissal_view(firing, NOW) is None
    assert dismissal_reason({"duration_seconds": 1, "reason": "  known  "}) == "known"
    assert dismissal_reason({"duration_seconds": 1, "reason": "   "}) is None


def test_cel_suppressed_is_evaluated_at_the_query_clock(firing):
    """Requirements: REV-49; alert operations 25, 29."""
    dismissed, _ = dismiss(firing, {"duration_seconds": 3600})
    end = dismissed["dismissed_until"]
    expression = compile_expression("suppressed")
    assert expression.evaluate(dismissed, end - timedelta(seconds=1)) is True
    assert expression.evaluate(dismissed, end) is False
    assert compile_expression("suppressed == false").to_elasticsearch(NOW) == {
        "bool": {
            "must_not": [
                {
                    "bool": {
                        "should": [
                            {"term": {"suppressed": True}},
                            {"range": {"dismissed_until": {"gt": int(NOW.timestamp() * 10**6)}}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            ]
        }
    }


def test_projection_carries_the_end_only_when_present(firing):
    """Requirements: REV-49; alert operations 29."""
    from keep.serialization import wire

    snapshot = dict(wire(firing), live=True, notes=[], incident_ids=[], active_incident_id=None)
    snapshot["last_received_at"] = snapshot["timestamp"]
    item = Projection(str(firing["tenant_id"]), 1, str(firing["id"]), 1, snapshot)
    plain = build_document(item)
    assert "dismissed_until" not in plain and "dismissed_until" not in plain["display"]
    dismissed, _ = dismiss(firing, {"duration_seconds": 3600})
    snapshot["dismissed_until"] = wire(dismissed)["dismissed_until"]
    document = build_document(Projection(item.tenant_id, 2, item.alert_id, 2, snapshot))
    assert document["dismissed_until"] == int(dismissed["dismissed_until"].timestamp() * 10**6)
    assert document["display"]["dismissed_until"] == snapshot["dismissed_until"]
