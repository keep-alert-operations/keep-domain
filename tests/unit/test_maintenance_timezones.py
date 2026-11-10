from datetime import UTC, datetime

import pytest

from keep.maintenance.timezones import (
    ScheduleError,
    local_to_utc,
    render_endpoint,
    validate_schedule,
)


def test_gap_and_fold_use_exact_roundtrip_and_explicit_occurrence():
    with pytest.raises(ScheduleError, match="does not exist"):
        local_to_utc("America/New_York", "2026-03-08T02:30:00")
    with pytest.raises(ScheduleError) as error:
        local_to_utc("America/New_York", "2026-11-01T01:30:00")
    assert error.value.code == "ambiguous_local_time"
    assert len(error.value.candidates) == 2
    first = local_to_utc("America/New_York", "2026-11-01T01:30:00", "first")
    second = local_to_utc("America/New_York", "2026-11-01T01:30:00", "second")
    assert first.utc == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
    assert second.utc == datetime(2026, 11, 1, 6, 30, tzinfo=UTC)
    assert first.offset_seconds == -14400 and second.offset_seconds == -18000
    assert first.tzdata_version == "2025.2"


@pytest.mark.parametrize(
    "zone,local,occurrence",
    [
        ("america/new_york", "2026-01-01T00:00:00", None),
        ("+02:00", "2026-01-01T00:00:00", None),
        ("UTC", "2026-01-01T00:00:00", "first"),
        ("UTC", "2026-01-01T00:00:00Z", None),
        ("UTC", "2026-01-01T00:00:00.123", None),
        ("UTC", "2026-02-30T00:00:00", None),
        ("Etc/GMT-12", "0001-01-01T00:00:00", None),
    ],
)
def test_invalid_timezone_occurrence_format_and_utc_overflow(zone, local, occurrence):
    with pytest.raises(ScheduleError):
        local_to_utc(zone, local, occurrence)


def test_timezone_only_render_preserves_instants_and_original_evidence():
    original = local_to_utc("UTC", "2026-09-22T12:00:00")
    rendered = render_endpoint(original, "Asia/Jerusalem")
    assert rendered["utc"] == original.utc.isoformat()
    assert rendered["original_local"] == "2026-09-22T12:00:00"
    assert rendered["local"] == "2026-09-22T15:00:00"
    assert rendered["rules_changed"] is False


def test_end_must_follow_authoritative_action_and_start():
    start = local_to_utc("UTC", "2026-09-22T10:00:00")
    end = local_to_utc("UTC", "2026-09-22T11:00:00")
    validate_schedule(start, end, datetime(2026, 9, 22, 10, 30, tzinfo=UTC))
    with pytest.raises(ScheduleError):
        validate_schedule(start, end, end.utc)
