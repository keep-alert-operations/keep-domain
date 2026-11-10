import json
import sys
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from keep import clock_health, pipeline_runtime


class Health:
    def __init__(self, *args):
        self.states = []

    def publish(self, **state):
        self.states.append(state)

    def wait(self, stopped, seconds):
        pass


def worker(monkeypatch, tmp_path, turns):
    """Run the real worker loop over a fake transport for ``turns`` turns."""
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
    reads = []
    real_open = open

    def counting_open(path, *args, **kwargs):
        reads.append(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(clock_health, "open", counting_open, raising=False)
    done = []

    class Transport:
        def __init__(self, *args):
            pass

        def turn(self):
            done.append(True)
            if len(done) == turns:
                # Stop the loop as SIGTERM would, after this turn.
                pipeline_runtime.signal.getsignal(pipeline_runtime.signal.SIGTERM)(None, None)
            return 1

        def close(self):
            pass

    return clock, Transport, done, reads


def test_worker_loop_reuses_clock_evidence_across_turns(monkeypatch, tmp_path):
    clock, transport, done, reads = worker(monkeypatch, tmp_path, turns=25)
    pipeline_runtime.run("source", transport)
    assert len(done) == 25
    # Host and database evidence share one file here: one read per interval.
    assert 1 <= len(reads) <= 3


def test_worker_loop_still_fails_closed_on_unhealthy_evidence(monkeypatch, tmp_path):
    clock, transport, done, reads = worker(monkeypatch, tmp_path, turns=1)
    clock.write_text(clock.read_text().replace("true", "false"))
    monkeypatch.setattr(sys, "argv", ["worker", "--once"])
    with pytest.raises(SystemExit):
        pipeline_runtime.run("source", transport)
    assert not done
