"""The worker loop waits for the next due background turn only without a Kafka poll."""

import sys
from types import SimpleNamespace

import pytest

from keep import pipeline_runtime
from keep.pipeline_runtime import IDLE_WAIT_SECONDS, MAX_IDLE_WAIT_SECONDS, idle_wait


class Background:
    def __init__(self, idle):
        self.idle, self.calls = idle, 0

    def __call__(self, db, settings):
        self.calls += 1
        return 0

    def idle_seconds(self):
        return self.idle


@pytest.mark.parametrize(
    ("transport", "idle", "expected"),
    [
        (object(), 30.0, IDLE_WAIT_SECONDS),  # The transport poll wakes on new input.
        (None, 30.0, MAX_IDLE_WAIT_SECONDS),  # Bounded: Kafka is retried within a second.
        (None, 0.4, 0.4),  # Wakes at the next due time.
        (None, 0.0, IDLE_WAIT_SECONDS),  # Due now: no busy spin either.
    ],
)
def test_idle_wait_follows_next_due_time_only_without_a_transport(transport, idle, expected):
    assert idle_wait(transport, Background(idle)) == pytest.approx(expected)


def test_idle_wait_is_unchanged_for_workers_without_due_time():
    assert idle_wait(None, None) == IDLE_WAIT_SECONDS
    assert idle_wait(None, lambda db, settings: 0) == IDLE_WAIT_SECONDS


def loop(monkeypatch, turns, transport_turn, background):
    settings = SimpleNamespace(
        worker_health_path=None,
        database_url=SimpleNamespace(get_secret_value=lambda: "postgresql://unused"),
        pool_size=1,
        deployment_epoch=1,
        capacity_profile=None,
    )
    waits = []

    class Health:
        def __init__(self, *args):
            pass

        def publish(self, **state):
            pass

        def wait(self, stopped, seconds):
            waits.append(seconds)
            if len(waits) == turns:
                stopped.set()

    monkeypatch.setattr(sys, "argv", ["worker"])
    monkeypatch.setattr(pipeline_runtime, "Settings", lambda role: settings)
    monkeypatch.setattr(pipeline_runtime, "WorkerHealth", Health)
    monkeypatch.setattr(
        pipeline_runtime, "Database", lambda *a, **k: SimpleNamespace(close=lambda: None)
    )
    monkeypatch.setattr(pipeline_runtime, "configure", lambda settings: None)
    monkeypatch.setattr(pipeline_runtime, "capture_profile", lambda *a, **k: None)
    monkeypatch.setattr(pipeline_runtime, "require_clock_health", lambda *a, **k: None)

    class Transport:
        def __init__(self, *args):
            pass

        def turn(self):
            return transport_turn()

        def close(self):
            pass

    pipeline_runtime.run("indexer", Transport, before_turn=background, transport_optional=True)
    return waits


def test_live_transport_is_polled_every_turn_while_background_is_idle(monkeypatch):
    polls, inputs = [], iter([0, 0, 3, 0])

    def turn():
        polls.append(True)
        return next(inputs)

    background = Background(30.0)
    waits = loop(monkeypatch, 4, turn, background)
    # New input is consumed on the next short poll, not after the idle time.
    assert len(polls) == 4 and background.calls == 4
    assert waits == [IDLE_WAIT_SECONDS, IDLE_WAIT_SECONDS, 0, IDLE_WAIT_SECONDS]


def test_kafka_outage_waits_for_the_next_due_background_turn(monkeypatch):
    def turn():
        raise RuntimeError("kafka unavailable")

    background = Background(0.25)
    waits = loop(monkeypatch, 3, turn, background)
    assert background.calls == 3
    assert waits == [pytest.approx(0.25)] * 3
