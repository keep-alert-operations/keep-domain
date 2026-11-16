"""Log records: fields, alert content, what is never written, and quality rules."""

import io
import json
import logging
import string
from uuid import uuid4

import pytest

from keep.observability import Repeats, alert_fields, bind, log_event, logs
from keep.observability.catalog import CATALOG, known_alert_field, known_field, register
from keep.shared.errors import AppError

log = logging.getLogger("keep.test.observability")

register(
    "test_alert_seen",
    logging.INFO,
    "Alert for {application} seen",
    "Test event carrying an alert.",
    required=("alert",),
)
register(
    "test_legacy_line",
    logging.WARNING,
    "Input held at partition {partition}",
    "Test event that keeps an existing message format.",
    text="test_legacy_line partition=%(partition)d lead_seconds=%(lead_seconds).3f",
)


def configured(**environ):
    stream = io.StringIO()
    logs.configure_logging(
        "processor",
        role="source",
        environ={"KEEP_ENVIRONMENT": "production", "HOSTNAME": "pod-1", **environ},
        stream=stream,
    )
    return stream


def written(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_record_has_the_contract_fields_and_a_plain_sentence():
    """Requirements: REV-74; observability 2."""
    stream = configured(KEEP_SERVICE_VERSION="abc123")
    log_event(log, "worker_ready_changed", role="source", state="ready")
    (record,) = written(stream)
    assert record["message"] == "Worker source is now ready"
    assert record["event"] == {"action": "worker_ready_changed"}
    assert record["log"] == {"level": "info", "logger": "keep.test.observability"}
    assert record["service"] == {
        "name": "processor",
        "version": "abc123",
        "environment": "production",
        "node": {"name": "pod-1"},
    }
    assert record["keep"] == {"role": "source", "state": "ready"}
    assert record["@timestamp"].endswith("Z") and "T" in record["@timestamp"]
    assert isinstance(record["process"]["pid"], int)


def test_python_message_stays_the_token_line(caplog):
    """Requirements: REV-74; observability 2. Existing message assertions keep working."""
    with caplog.at_level(logging.INFO, logger=log.name):
        log_event(log, "worker_ready_changed", role="source", state="ready")
        log_event(log, "test_legacy_line", partition=3, lead_seconds=0.25)
    assert [record.getMessage() for record in caplog.records] == [
        "worker_ready_changed role=source state=ready",
        "test_legacy_line partition=3 lead_seconds=0.250",
    ]


def test_bound_fields_reach_every_record_including_plain_logging_calls():
    """Requirements: REV-74; observability 2."""
    stream = configured()
    tenant = uuid4()
    with bind(request_id="request-1", tenant_id=tenant):
        log.warning("legacy_token partition=%d", 3)
    log.warning("Free text outside any request")
    inside, outside = written(stream)
    assert inside["http"]["request"]["id"] == "request-1"
    assert inside["keep"]["tenant_id"] == str(tenant)
    assert inside["event"] == {"action": "legacy_token", "outcome": "failure"}
    assert inside["message"] == "legacy_token partition=3"
    assert outside["event"]["action"] == "log"
    assert "http" not in outside


def test_field_types_are_fixed_and_duration_is_nanoseconds():
    """Requirements: REV-74; observability 2. One type per field in every record."""
    stream = configured()
    log_event(
        log,
        "http_request",
        ok=True,
        request_id=uuid4(),
        method="GET",
        route="/api/tenants/{tenant_id}/alerts",
        status="200",
        duration=0.25,
        body_bytes=12.0,
    )
    (record,) = written(stream)
    assert record["http"]["response"]["status_code"] == 200
    assert record["http"]["request"]["body"]["bytes"] == 12
    assert isinstance(record["http"]["request"]["id"], str)
    assert record["event"] == {
        "action": "http_request",
        "outcome": "success",
        "duration": 250_000_000,
    }


def test_exception_text_is_never_written(caplog):
    """Requirements: REV-74; observability 4."""
    stream = configured()
    canary = "canary-password=hunter2"
    try:
        raise RuntimeError(canary)
    except RuntimeError as error:
        log_event(log, "process_unhandled_error", exc=error, origin="main")
        log.exception("legacy_failure")
    try:
        raise AppError("revision_conflict", canary, 409)
    except AppError as error:
        log_event(log, "process_unhandled_error", exc=error, origin="thread")
    assert canary not in stream.getvalue()
    catalogued, plain, coded = written(stream)
    assert catalogued["error"]["type"] == "builtins.RuntimeError"
    assert "test_observability_logs.py" in catalogued["error"]["stack_trace"]
    assert plain["error"]["type"] == "builtins.RuntimeError"
    assert coded["error"]["code"] == "revision_conflict"
    assert coded["message"] == "Unhandled keep.shared.errors.AppError in thread"


def test_unregistered_events_and_fields_fail_under_test():
    """Requirements: REV-74; observability 2 and 5."""
    configured()
    with pytest.raises(KeyError):
        log_event(log, "never_registered")
    with pytest.raises(KeyError):
        log_event(log, "worker_ready_changed", role="source", state="ready", stray=1)
    with pytest.raises(KeyError):
        log_event(log, "worker_ready_changed", role="source")
    with pytest.raises(KeyError):
        log_event(log, "test_alert_seen", alert={"sender_field": "x"})


def test_whole_alert_uses_only_its_own_names_and_native_limits():
    """Requirements: REV-74; observability 3."""
    stream = configured()
    alert_id = uuid4()
    submitted = {
        "application": "billing",
        "component": "database",
        "node_name": "db-1",
        "name": "Disk full",
        "site": "eu-1",
        "severity": "critical",
        "status": "firing",
        "message": "m" * 9000,
        "impact": "Payments are delayed",
        "runbook_url": "https://runbooks.example/disk",
        "time_created": "12-11-2026 10:00:00",
        "sender.invented": "never a field",
        "nested": {"x": 1},
    }
    whole = alert_fields(
        submitted, alert_id=alert_id, key_digest=b"\x01\xab", native_version="v2", whole=True
    )
    assert whole["key_digest"] == "01ab" and whole["id"] == str(alert_id)
    assert len(whole["message"]) == 8192
    assert "sender.invented" not in whole and "nested" not in whole
    identifying = alert_fields(submitted, alert_id=alert_id)
    assert set(identifying) == {
        "id",
        "application",
        "component",
        "node_name",
        "name",
        "site",
        "severity",
        "status",
    }
    log_event(log, "test_alert_seen", alert=whole)
    (record,) = written(stream)
    assert record["message"] == "Alert for billing seen"
    alert = record["keep"]["alert"]
    assert alert["application"] == "billing" and alert["component"] == "database"
    assert alert["impact"] == "Payments are delayed"
    assert alert["id"] == str(alert_id) and alert["native_version"] == "v2"


def test_level_setting_and_text_format():
    """Requirements: REV-74; observability 2 and 10."""
    quiet = configured(KEEP_LOG_LEVEL="warning")
    log_event(log, "worker_ready_changed", role="source", state="ready")
    assert quiet.getvalue() == ""
    text = configured(KEEP_LOG_FORMAT="text")
    with bind(request_id="request-9"):
        log_event(log, "worker_ready_changed", role="source", state="ready")
    line = text.getvalue().strip()
    assert line.endswith("info worker_ready_changed role=source state=ready request_id=request-9")


def test_persisting_condition_is_recorded_at_most_once_a_minute(monkeypatch):
    """Requirements: REV-74; observability 5."""
    now = [100.0]
    monkeypatch.setattr(logs, "monotonic", lambda: now[0])
    repeats = Repeats()
    assert repeats.due("kafka") == 1
    assert repeats.due("kafka") is None and repeats.due("kafka") is None
    assert repeats.due("other") == 1
    now[0] += 61
    assert repeats.due("kafka") == 3
    repeats.clear("kafka")
    assert repeats.due("kafka") == 1


def test_every_catalogued_event_is_documented_and_uses_registered_fields():
    """Requirements: REV-74; observability 5."""
    for name, entry in CATALOG.items():
        assert entry.message and entry.doc, name
        for _, field, _, _ in string.Formatter().parse(entry.message):
            assert field is None or known_field(field) or known_alert_field(field), (name, field)
