"""Bounded process lifecycle shared by independently packaged Kafka workers."""

import argparse
import json
import logging
import signal
from threading import Event
from time import monotonic

from keep.alert_notifications import configure
from keep.clock_health import ClockEvidenceCache, require_clock_health
from keep.config import Settings
from keep.db import Database
from keep.observability import Repeats, configure_logging, log_event, start_metrics_server
from keep.observability.logs import SERVICES
from keep.observability.metrics import counter, gauge, histogram
from keep.visibility.runtime import capture_profile
from keep.worker_health import WorkerHealth

log = logging.getLogger(__name__)
IDLE_WAIT_SECONDS = 0.01
MAX_IDLE_WAIT_SECONDS = 1.0

# REV-74, observability 7: what every worker's loop reports about itself.
TURNS = counter("keep_worker_turns_total", "Worker loop turns.", ("role", "outcome"))
TURN_SECONDS = histogram("keep_worker_turn_seconds", "Duration of one worker turn.", ("role",))
LAST_TURN = gauge(
    "keep_worker_last_turn_timestamp_seconds", "When the last turn finished.", ("role",)
)
READY = gauge("keep_worker_ready", "1 while the worker reports ready.", ("role",))
DRAINING = gauge("keep_worker_draining", "1 while the worker is draining.", ("role",))
FAILURES = counter(
    "keep_worker_capability_failures_total",
    "Failed worker turns, by controlled error code.",
    ("role", "error_code"),
)
RESTARTS = counter(
    "keep_worker_transport_restarts_total", "Kafka clients discarded after a failed turn.", ("role",)
)


def failure_code(error):
    """The controlled code of a failed turn; a closed set, safe as a metric label."""
    code = getattr(error, "code", None)
    if isinstance(code, str) and code.isidentifier():
        return code
    module = type(error).__module__
    for prefix, name in (
        ("psycopg", "database"),
        ("confluent_kafka", "kafka"),
        ("cimpl", "kafka"),
        ("elastic", "elasticsearch"),
    ):
        if module.startswith(prefix):
            return name
    return "other"


def idle_wait(transport, before_turn):
    """Seconds to wait after a turn without progress.

    A live transport's bounded poll already waits for, and wakes on, new input,
    so the short pause is kept. Without one (a Kafka outage), only background
    work remains: sleep until its next due time, if it reports one, bounded so
    the transport is retried within a second. A stop request ends any wait.
    """
    idle_seconds = getattr(before_turn, "idle_seconds", None)
    if transport is not None or idle_seconds is None:
        return IDLE_WAIT_SECONDS
    return min(MAX_IDLE_WAIT_SECONDS, max(IDLE_WAIT_SECONDS, idle_seconds()))


def run(role, make_transport, *, before_turn=None, transport_optional=False):
    parser = argparse.ArgumentParser(description=f"Keep {role} worker")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    # Before anything that can fail, so a failed start is recorded too (REV-74).
    configure_logging(SERVICES.get(role, role), role=role)
    start_metrics_server()
    settings = Settings(role=role)
    health = WorkerHealth(settings.worker_health_path, role)
    health.publish()
    repeats = Repeats()
    reported = None

    def publish_ready(value):
        nonlocal reported
        health.publish(ready=value)
        READY.labels(role).set(1 if value else 0)
        if value != reported:
            reported = value
            log_event(
                log, "worker_ready_changed", role=role, state="ready" if value else "not_ready"
            )

    def degraded(event, error):
        # A persisting condition: recorded when it starts, then once a minute.
        count = repeats.due(event)
        if count:
            log_event(log, event, exc=error, role=role, repeats=count)
    db = Database(
        settings.database_url.get_secret_value(),
        settings.pool_size,
        deployment_epoch=settings.deployment_epoch,
    )
    transport = None
    stopped = Event()
    previous = {}
    # Each turn checks clock health; unchanged evidence files are not re-read.
    clock_evidence = ClockEvidenceCache()

    def stop(*_):
        # Runs in a signal handler: publish and return; the loop records the stop.
        health.publish(draining=True)
        stopped.set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, stop)
        configure(settings)
        profile = (
            json.loads(settings.capacity_profile.read_text()) if settings.capacity_profile else None
        )
        capture_profile(profile, deployment_epoch=settings.deployment_epoch)
        log_event(log, "process_started", role=role)
        while not stopped.is_set():
            progress = 0
            failed = False
            began = monotonic()
            try:
                require_clock_health(settings, cache=clock_evidence)
                transport_failed = False
                try:
                    if transport is None:
                        transport = make_transport(db, settings, profile)
                    progress = transport.turn()
                    repeats.clear("search_kafka_degraded_reconciliation_active")
                except Exception as error:
                    if transport is not None:
                        transport.close()
                        transport = None
                        RESTARTS.labels(role).inc()
                    if not transport_optional:
                        raise
                    transport_failed = True
                    degraded("search_kafka_degraded_reconciliation_active", error)
                if before_turn is not None:
                    try:
                        progress += before_turn(db, settings) or 0
                        repeats.clear("search_reconciliation_degraded_hints_active")
                    except Exception as error:
                        # Authority scan failure must not prevent independent
                        # Kafka hints from repairing healthy tenants.
                        if transport_failed:
                            raise
                        degraded("search_reconciliation_degraded_hints_active", error)
                publish_ready(True)
                repeats.clear("worker_capability_unavailable")
            except Exception as error:
                failed = True
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:
                        pass  # The client is discarded either way; counted just below.
                    transport = None
                    RESTARTS.labels(role).inc()
                publish_ready(False)
                # The class and controlled code of the failure, which this record
                # used to omit; never the exception's text.
                FAILURES.labels(role, failure_code(error)).inc()
                degraded("worker_capability_unavailable", error)
                if args.once:
                    raise SystemExit(1) from None
            finally:
                TURNS.labels(role, "failed" if failed else "progress" if progress else "idle").inc()
                TURN_SECONDS.labels(role).observe(monotonic() - began)
                LAST_TURN.labels(role).set_to_current_time()
            if args.once:
                return
            health.wait(
                stopped, 1 if failed else 0 if progress else idle_wait(transport, before_turn)
            )
    finally:
        health.publish(draining=True)
        DRAINING.labels(role).set(1)
        log_event(
            log, "process_stopping", role=role, reason="signal" if stopped.is_set() else "exit"
        )
        try:
            if transport is not None:
                transport.close()
        finally:
            close_background = getattr(before_turn, "close", None)
            try:
                if close_background:
                    close_background()
            finally:
                try:
                    db.close()
                finally:
                    for sig, handler in previous.items():
                        signal.signal(sig, handler)
