"""An alert's steps inside one service: ordered, carrying its identifiers, true after commit."""

import io
import json
import logging

import pytest

from keep.observability import Flow, alert_fields, configure_logging, flow as alert_flow, logs


@pytest.fixture
def records():
    stream = io.StringIO()
    configure_logging("processor", role="source", environ={}, stream=stream)
    return lambda: [json.loads(line) for line in stream.getvalue().splitlines()]


LOG = logging.getLogger("keep.test.flow")
ALERT = {"application": "billing", "component": "database", "severity": "critical"}


def new_flow(**fields):
    return Flow(LOG, alert={"id": "a-1", **ALERT}, changed_event_id="e-1", **fields)


def test_every_step_carries_the_pass_identifiers_and_its_order(records):
    """Requirements: REV-74; observability 3. Steps sort even inside one millisecond."""
    flow = new_flow(tenant_id="t-1")
    flow.step("alert_change_consumed", partition=3, offset=41)
    flow.know(incident_id="i-1")
    flow.step("alert_correlated", outcome="attached")
    first, second = records()
    assert [first["event"]["sequence"], second["event"]["sequence"]] == [1, 2]
    assert [first["event"]["action"], second["event"]["action"]] == [
        "alert_change_consumed",
        "alert_correlated",
    ]
    for record in (first, second):
        assert record["keep"]["alert"]["id"] == "a-1"
        assert record["keep"]["alert"]["application"] == "billing"
        assert record["keep"]["changed_event_id"] == "e-1"
        assert record["keep"]["tenant_id"] == "t-1"
    assert "incident_id" not in first["keep"] and second["keep"]["incident_id"] == "i-1"


def test_a_held_step_is_written_only_after_its_transaction_commits(records):
    """Requirements: REV-74; observability 3. A rolled-back effect leaves no record."""
    with pytest.raises(RuntimeError):
        with new_flow() as flow:
            alert_flow.note("alert_correlated", outcome="attached")
            assert records() == []
            raise RuntimeError("rolled back")
    flow.settle()
    assert records() == []

    with new_flow() as flow:
        alert_flow.note(
            "alert_correlated", learned={"incident_id": "i-9"}, outcome="incident_created"
        )
        assert [step["outcome"] for step in flow.held("alert_correlated")] == [
            "incident_created"
        ]
    flow.settle()
    (record,) = records()
    assert record["keep"]["outcome"] == "incident_created"
    assert record["keep"]["incident_id"] == "i-9"
    assert flow.seen == ["alert_correlated"]


def test_a_note_outside_any_flow_records_nothing(records):
    """Requirements: REV-74; observability 3."""
    assert alert_flow.active() is None
    alert_flow.note("alert_correlated", outcome="attached")
    assert records() == []


def test_a_step_about_another_alert_names_only_that_alert(records):
    """Requirements: REV-74; observability 3. A decision may attach other alerts too."""
    flow = new_flow()
    flow.step(
        "alert_incident_attached",
        alert=alert_fields({"application": "payments"}, alert_id="a-2"),
        incident_id="i-1",
        rule_id="r-1",
        outcome="incident_existing",
    )
    flow.step("alert_correlated", outcome="attached")
    other, own = records()
    assert other["keep"]["alert"] == {"id": "a-2", "application": "payments"}
    assert own["keep"]["alert"]["id"] == "a-1"
    assert own["keep"]["alert"]["component"] == "database"


def test_outcome_only_setting_drops_progress_steps_but_never_failures(records, monkeypatch):
    """Requirements: REV-74; observability 3 and 10."""
    monkeypatch.setattr(logs, "DETAIL", False)
    flow = new_flow()
    flow.step("alert_change_consumed", detail=True, partition=3, offset=41)
    flow.step("alert_change_consumed", detail=True, ok=False, partition=3, offset=41)
    flow.step("alert_correlated", outcome="no_incident")
    failed, outcome = records()
    assert failed["event"]["outcome"] == "failure"
    assert outcome["event"]["action"] == "alert_correlated"
    assert [failed["event"]["sequence"], outcome["event"]["sequence"]] == [1, 2]


def test_configuration_reads_the_alert_steps_setting():
    """Requirements: REV-74; observability 10."""
    configure_logging(
        "processor", environ={"KEEP_LOG_ALERT_STEPS": "outcome"}, stream=io.StringIO()
    )
    assert logs.DETAIL is False
    configure_logging("processor", environ={}, stream=io.StringIO())
    assert logs.DETAIL is True


def test_a_list_field_is_written_as_bounded_keywords(records):
    """Requirements: REV-74; observability 2 and 3."""
    logs.log_event(LOG, "alert_refused", error_code="invalid_field", fields=["sev erity", 7])
    (record,) = records()
    assert record["keep"]["fields"] == ["sev erity", "7"]
