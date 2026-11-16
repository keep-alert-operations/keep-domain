"""What the worker loop records about its own turns and failures."""

import json
import logging
import sys
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from keep import pipeline_runtime
from keep.observability.metrics import REGISTRY
from keep.shared.errors import unavailable


class Health:
    def __init__(self, *args):
        self.states = []

    def publish(self, **state):
        self.states.append(state)

    def wait(self, stopped, seconds):
        pass


def sample(name, **labels):
    return REGISTRY.get_sample_value(name, labels) or 0.0


@pytest.fixture
def worker(monkeypatch, tmp_path):
    """The real loop over a scripted transport; ``turns`` are results or exceptions."""
    clock = tmp_path / "clock.json"
    clock.write_text(
        json.dumps(
            {
                "offset_seconds": 0,
                "measured_at": datetime.now(UTC).isoformat(),
                "synchronized": True,
            }
        )
    )
    settings = SimpleNamespace(
        role="source",
        environment="production",
        worker_health_path=None,
        database_url=SimpleNamespace(get_secret_value=lambda: "postgresql://unused"),
        pool_size=1,
        deployment_epoch=1,
        capacity_profile=None,
        clock_health_file=clock,
        database_clock_health_file=clock,
    )
    monkeypatch.setattr(sys, "argv", ["worker"])
    monkeypatch.setattr(pipeline_runtime, "Settings", lambda role: settings)
    monkeypatch.setattr(pipeline_runtime, "WorkerHealth", Health)
    monkeypatch.setattr(
        pipeline_runtime, "Database", lambda *a, **k: SimpleNamespace(close=lambda: None)
    )
    monkeypatch.setattr(pipeline_runtime, "configure", lambda settings: None)
    monkeypatch.setattr(pipeline_runtime, "capture_profile", lambda *a, **k: None)
    monkeypatch.setattr(pipeline_runtime, "configure_logging", lambda *a, **k: None)

    def run(turns):
        script = list(turns)

        class Transport:
            def __init__(self, *args):
                pass

            def turn(self):
                result = script.pop(0)
                if not script:
                    # Stop the loop as SIGTERM would, after this turn.
                    pipeline_runtime.signal.getsignal(pipeline_runtime.signal.SIGTERM)(None, None)
                if isinstance(result, Exception):
                    raise result
                return result

            def close(self):
                pass

        pipeline_runtime.run("source", Transport)

    return run


def events(caplog, name):
    return [r for r in caplog.records if getattr(r, "keep_event", None) == name]


def test_a_failed_turn_records_its_class_and_controlled_code(worker, caplog):
    """Requirements: REV-74; observability 2 and 4. The record used to carry neither."""
    code = dict(role="source", error_code="kafka_source_consume_failed")
    before = sample("keep_worker_capability_failures_total", **code)
    failed = sample("keep_worker_turns_total", role="source", outcome="failed")
    with caplog.at_level(logging.INFO, logger=pipeline_runtime.__name__):
        worker([unavailable("kafka_source_consume_failed")])
    (record,) = events(caplog, "worker_capability_unavailable")
    assert record.levelno == logging.WARNING
    assert record.keep_fields["error_code"] == "kafka_source_consume_failed"
    assert record.keep_fields["error_class"] == "keep.shared.errors.AppError"
    assert record.keep_fields["role"] == "source" and record.keep_fields["repeats"] == 1
    assert sample("keep_worker_capability_failures_total", **code) == before + 1
    assert sample("keep_worker_turns_total", role="source", outcome="failed") == failed + 1
    assert sample("keep_worker_ready", role="source") == 0


def test_a_persisting_failure_is_logged_once_but_counted_every_turn(worker, caplog):
    """Requirements: REV-74; observability 5."""
    other = dict(role="source", error_code="other")
    before = sample("keep_worker_capability_failures_total", **other)
    restarts = sample("keep_worker_transport_restarts_total", role="source")
    with caplog.at_level(logging.INFO, logger=pipeline_runtime.__name__):
        worker([RuntimeError("canary-secret")] * 4)
    assert len(events(caplog, "worker_capability_unavailable")) == 1
    assert "canary-secret" not in caplog.text
    assert sample("keep_worker_capability_failures_total", **other) == before + 4
    assert sample("keep_worker_transport_restarts_total", role="source") == restarts + 4


def test_readiness_is_recorded_only_when_it_changes(worker, caplog):
    """Requirements: REV-74; observability 5."""
    progress = sample("keep_worker_turns_total", role="source", outcome="progress")
    idle = sample("keep_worker_turns_total", role="source", outcome="idle")
    with caplog.at_level(logging.INFO, logger=pipeline_runtime.__name__):
        worker([1, 0, 1, RuntimeError("down"), 1])
    states = [r.keep_fields["state"] for r in events(caplog, "worker_ready_changed")]
    assert states == ["ready", "not_ready", "ready"]
    assert len(events(caplog, "process_started")) == 1
    assert len(events(caplog, "process_stopping")) == 1
    assert sample("keep_worker_turns_total", role="source", outcome="progress") == progress + 3
    assert sample("keep_worker_turns_total", role="source", outcome="idle") == idle + 1
    assert sample("keep_worker_ready", role="source") == 1
    assert sample("keep_worker_last_turn_timestamp_seconds", role="source") > 0


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (unavailable("clock_untrusted"), "clock_untrusted"),
        (RuntimeError("x"), "other"),
        (type("OperationalError", (Exception,), {"__module__": "psycopg.errors"})(), "database"),
        (type("KafkaException", (Exception,), {"__module__": "confluent_kafka"})(), "kafka"),
    ],
)
def test_failure_codes_are_a_closed_set(error, expected):
    """Requirements: REV-74; observability 7. Safe as a metric label."""
    assert pipeline_runtime.failure_code(error) == expected
