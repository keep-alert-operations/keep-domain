from datetime import UTC, datetime
from uuid import uuid4
import pytest
from keep.ingestion.native import canonical, identity, parse_json, validate_native
from keep.alerts.lifecycle import apply_source, apply_command
from keep.shared.errors import AppError


@pytest.mark.parametrize(
    "field",
    ["application", "object", "node_name", "message", "operator", "time_created", "severity"],
)
def test_missing_required_native_field(v1, field):
    del v1[field]
    with pytest.raises(AppError):
        validate_native(v1, "v1", canonical(v1))


@pytest.mark.parametrize("value", [None, True, 1, [], {}, "", "  "])
def test_no_native_coercion(v1, value):
    v1["message"] = value
    with pytest.raises(AppError):
        validate_native(v1, "v1", canonical(v1))


@pytest.mark.parametrize("field", ["history_id", "tenant_id", "to_show", "timestamp", "status"])
def test_generated_fields_never_accepted(v1, field):
    v1[field] = "injected"
    with pytest.raises(AppError):
        validate_native(v1, "v1", canonical(v1))


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'"\\ud800"', b"\xff"]
)
def test_invalid_json_boundaries(raw):
    with pytest.raises(AppError):
        parse_json(raw)


def test_v2_identity_preserves_exact_unicode_control_spelling():
    operator = str(uuid4())
    source = {
        "application": "a",
        "component": "b",
        "severity": "high",
        "site": "s",
        "impact": "line\nnext",
        "runbook_url": "https://example.invalid/r",
        "message": "one",
        "status": "firing",
    }
    key, _, material = identity(source, "v2", operator)
    assert b"\\u000a" in material
    assert identity({**source, "message": "other", "status": "resolved"}, "v2", operator)[0] == key
    assert identity({**source, "impact": "changed"}, "v2", operator)[0] != key


def test_first_clear_then_manual_open_keeps_source_time(v1):
    v1["severity"] = "clear"
    when = datetime(2026, 9, 22, tzinfo=UTC)
    current, _ = apply_source(
        None,
        {
            "payload": v1,
            "received_at": when,
            "version": "v1",
            "tenant_id": uuid4(),
            "id": uuid4(),
            "key_field": "test",
        },
    )
    assert current["occurrence_number"] == 0 and current["occurrence_id"] is None
    original_time = current["time_created"]
    opened, changed = apply_command(current, "set_status", "firing", uuid4(), when)
    assert changed and opened["occurrence_number"] == 1
    assert opened["time_created"] == original_time and opened["severity"] == "clear"
