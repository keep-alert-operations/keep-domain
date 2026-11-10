"""Ephemeral process probes; PostgreSQL remains the durable work authority."""

import argparse
import json
import os
from pathlib import Path
from time import monotonic, sleep


class WorkerHealth:
    def __init__(self, path: Path | None, role: str):
        self.path = path
        self.role = role
        self.ready = False
        self.draining = False
        self._last_attempt_at = None
        self._last_attempt_state = None

    def publish(self, *, ready=None, draining=None):
        if ready is not None:
            self.ready = ready
        if draining is not None:
            self.draining = draining
        if self.path is None:
            return
        now = monotonic()
        current = (self.ready, self.draining)
        if (
            current == self._last_attempt_state
            and self._last_attempt_at is not None
            and 0 <= now - self._last_attempt_at < 1
        ):
            return
        # Bound unchanged writes (including sharing-violation retries) without
        # delaying state transitions. Only successful replacement refreshes the
        # probe file, so persistent failures still expire its old heartbeat.
        self._last_attempt_at = now
        self._last_attempt_state = current
        state = {
            "version": 1,
            "pid": os.getpid(),
            "role": self.role,
            "heartbeat": now,
            "ready": self.ready,
            "draining": self.draining,
        }
        temporary = self.path.with_suffix(".new")
        temporary.write_text(json.dumps(state), encoding="utf-8")
        for attempt in range(3):
            try:
                temporary.replace(self.path)
                return
            except PermissionError:
                # Windows readers can briefly deny atomic replacement. A probe
                # must expire if publication stays blocked, not stop durable work.
                if attempt < 2:
                    sleep(0.01)

    def wait(self, stop_event, seconds):
        deadline = monotonic() + seconds
        while not stop_event.is_set():
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            self.publish()
            stop_event.wait(min(5, remaining))


def probe(path: Path, kind: str, max_age: float):
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        age = monotonic() - state["heartbeat"]
        if state["version"] != 1 or not 0 <= age <= max_age:
            return False
        if kind == "ready":
            return state["ready"] is True and state["draining"] is False
        return kind == "live"
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("live", "ready"))
    parser.add_argument("--max-age", type=float, required=True)
    args = parser.parse_args()
    if args.max_age <= 0:
        parser.error("A positive heartbeat age is required")
    configured = os.getenv("KEEP_WORKER_HEALTH_PATH")
    raise SystemExit(0 if configured and probe(Path(configured), args.kind, args.max_age) else 1)


if __name__ == "__main__":
    main()
