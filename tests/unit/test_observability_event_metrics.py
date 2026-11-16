"""Every recorded event moves a metric of the same name; Kafka clients report their numbers."""

import json
import logging

import pytest

from keep.kafka_changed import HELD, PartitionRetries
from keep.observability import Flow, kafka, log_event, logs
from keep.observability.metrics import REGISTRY
from keep.observability.testing import capture_records

LOG = logging.getLogger("keep.test.metrics")


def value(name, **labels):
    return REGISTRY.get_sample_value(name, labels) or 0.0


def events(event, outcome, reason=""):
    return value("keep_events_total", event=event, outcome=outcome, reason=reason)


@pytest.fixture
def records():
    return capture_records("processor", "source")


def test_an_event_is_counted_by_its_outcome_and_reason(records):
    """Requirements: REV-74; observability 7. Each logged flow and failure is a number."""
    applied = events("alert_applied", "resolved")
    refused = events("alert_refused", "failure", "identity_conflict")
    flow = Flow(LOG, alert={"id": "a-1"})
    flow.step("alert_applied", outcome="resolved", status_after="resolved", revision=2)
    flow.step("alert_refused", error_code="identity_conflict")
    assert events("alert_applied", "resolved") == applied + 1
    assert events("alert_refused", "failure", "identity_conflict") == refused + 1


def test_an_event_is_counted_even_when_it_is_not_written(records, monkeypatch):
    """Requirements: REV-74; observability 7 and 10. Numbers do not depend on log settings."""
    before = events("alert_change_consumed", "success")
    monkeypatch.setattr(logs, "DETAIL", False)
    flow = Flow(LOG, alert={"id": "a-1"}, changed_event_id="e-1")
    flow.step("alert_change_consumed", detail=True, partition=1, offset=2)
    quiet = logging.getLogger("keep.test.metrics.quiet")
    quiet.setLevel(logging.ERROR)
    Flow(quiet, alert={"id": "a-1"}, changed_event_id="e-1").step(
        "alert_change_consumed", partition=1, offset=2
    )
    assert records() == []
    assert events("alert_change_consumed", "success") == before + 2


def test_timings_on_an_event_become_histograms(records):
    """Requirements: REV-74; observability 7. Buckets hold the objectives' thresholds."""
    count = value("keep_event_delay_seconds_count", event="alert_correlated")
    within = value("keep_event_delay_seconds_bucket", event="alert_correlated", le="2.0")
    took = value("keep_event_duration_seconds_count", event="alert_correlated")
    flow = Flow(LOG, alert={"id": "a-1"}, changed_event_id="e-1")
    flow.step("alert_correlated", outcome="no_incident", delay_seconds=1.5, duration=0.2)
    flow.step("alert_correlated", outcome="no_incident", delay_seconds=3.0, duration=0.2)
    assert value("keep_event_delay_seconds_count", event="alert_correlated") == count + 2
    assert value("keep_event_delay_seconds_bucket", event="alert_correlated", le="2.0") == within + 1
    assert value("keep_event_duration_seconds_count", event="alert_correlated") == took + 2


def test_a_held_delay_is_read_when_the_step_is_written(records):
    """Requirements: REV-74; observability 3 and 7. The delay ends at the commit."""
    clock = iter([4.0])
    with Flow(LOG, alert={"id": "a-1"}) as flow:
        flow.note(
            "alert_applied",
            outcome="created",
            status_after="firing",
            revision=1,
            delay_seconds=lambda: next(clock),
        )
    flow.settle()
    (record,) = records()
    assert record["keep"]["delay_seconds"] == 4.0


def test_requests_are_left_to_the_request_metrics(records):
    """Requirements: REV-74; observability 7. One count per request, with its route."""
    before = events("http_request", "success")
    log_event(LOG, "http_request", ok=True, request_id="r", method="GET", route="/x", status=200)
    assert events("http_request", "success") == before


def report(**overrides):
    body = {
        "name": "rdkafka#consumer-1",
        "type": "consumer",
        "msg_cnt": 0,
        "brokers": {
            "bootstrap": {"nodeid": -1, "state": "UP"},
            "kafka:29092/1": {"nodeid": 1, "state": "UP"},
        },
        "topics": {
            "keep.test.alerts.changed": {
                "partitions": {
                    "0": {"consumer_lag": 7, "committed_offset": 40, "hi_offset": 47},
                    "1": {"consumer_lag": -1, "committed_offset": -1001, "hi_offset": 9},
                    "-1": {"consumer_lag": -1},
                }
            }
        },
    }
    return json.dumps({**body, **overrides})


def test_consumer_statistics_set_lag_for_the_partitions_it_reads():
    """Requirements: REV-74; observability 7."""
    kafka.record(report())
    labels = dict(topic="keep.test.alerts.changed", partition="0")
    assert value("keep_kafka_consumer_lag_messages", **labels) == 7
    assert value("keep_kafka_consumer_committed_offset", **labels) == 40
    assert value("keep_kafka_partition_end_offset", **labels) == 47
    # A partition another consumer reads reports no lag here.
    other = dict(topic="keep.test.alerts.changed", partition="1")
    assert REGISTRY.get_sample_value("keep_kafka_consumer_lag_messages", other) is None
    assert value("keep_kafka_brokers", kind="consumer", state="up") == 1


def test_a_consumer_committing_through_its_producer_still_reports_lag():
    """Requirements: REV-74; observability 7. The source processor commits in a transaction."""
    topics = {
        "keep.test.alerts.received": {
            "partitions": {
                "2": {"consumer_lag": -1, "app_offset": 30, "ls_offset": 42, "hi_offset": 43},
                # Another consumer's partition: nothing is fetched here.
                "3": {"consumer_lag": -1, "app_offset": -1001, "fetch_state": "none",
                      "next_offset": 0, "ls_offset": 5, "hi_offset": 5},
                # Assigned but idle since the restart: lag from where it fetches next.
                "4": {"consumer_lag": -1, "app_offset": -1001, "fetch_state": "active",
                      "next_offset": 90, "ls_offset": 90, "hi_offset": 90},
            }
        }
    }
    kafka.record(report(topics=topics))
    assert value("keep_kafka_consumer_lag_messages", topic="keep.test.alerts.received", partition="2") == 12
    unread = dict(topic="keep.test.alerts.received", partition="3")
    assert REGISTRY.get_sample_value("keep_kafka_consumer_lag_messages", unread) is None
    idle = dict(topic="keep.test.alerts.received", partition="4")
    assert REGISTRY.get_sample_value("keep_kafka_consumer_lag_messages", idle) == 0


def test_producer_statistics_sum_the_queues_of_every_producer():
    """Requirements: REV-74; observability 7."""
    kafka.record(report(name="rdkafka#producer-1", type="producer", msg_cnt=3, topics={}))
    kafka.record(report(name="rdkafka#producer-2", type="producer", msg_cnt=4, topics={}))
    assert value("keep_kafka_client_queue_messages", kind="producer") == 7


def test_unreadable_statistics_are_counted_and_never_raise():
    """Requirements: REV-74; observability 7. The callback runs inside the client."""
    before = value("keep_kafka_statistics_errors_total")
    kafka.record("not json")
    assert value("keep_kafka_statistics_errors_total") == before + 1


def test_statistics_are_on_only_where_metrics_are():
    """Requirements: REV-74; observability 10."""
    assert kafka.statistics_options({}) == {}
    options = kafka.statistics_options({"KEEP_METRICS_PORT": "59101"})
    assert options["statistics.interval.ms"] == 5000 and options["stats_cb"] is kafka.record


def test_held_partitions_are_a_gauge_by_state():
    """Requirements: REV-74; observability 7."""
    from types import SimpleNamespace
    from unittest.mock import Mock

    retries = PartitionRetries(Mock())
    retries.failed = {("t", 0): (SimpleNamespace(), 5.0), ("t", 1): (SimpleNamespace(), float("inf"))}
    retries._count()
    assert HELD.labels("retrying")._value.get() == 1 and HELD.labels("fenced")._value.get() == 1
    retries.revoke([SimpleNamespace(topic="t", partition=0), SimpleNamespace(topic="t", partition=1)])
    assert HELD.labels("retrying")._value.get() == 0 and HELD.labels("fenced")._value.get() == 0


def test_the_shared_client_options_never_carry_a_statistics_callback(monkeypatch):
    """Requirements: REV-74; observability 7.

    They reach short-lived clients too (administration, probes, the source
    processor's transactional producers), and a statistics callback on a client
    made or dropped inside another client's callback crashes the Kafka library.
    """
    from types import SimpleNamespace

    from keep.service_clients import kafka_options

    monkeypatch.setenv("KEEP_METRICS_PORT", "59101")
    options = kafka_options(SimpleNamespace(kafka_bootstrap="broker:9092"))
    assert "stats_cb" not in options and "statistics.interval.ms" not in options
