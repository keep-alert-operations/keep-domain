"""Bounded process lifecycle shared by independently packaged Kafka workers."""

import argparse
import json
import logging
import signal
from threading import Event

from appchi.alert_notifications import configure
from appchi.clock_health import ClockEvidenceCache, require_clock_health
from appchi.config import Settings
from appchi.db import Database
from appchi.visibility.runtime import capture_profile
from appchi.worker_health import WorkerHealth

log = logging.getLogger(__name__)
IDLE_WAIT_SECONDS = 0.01
MAX_IDLE_WAIT_SECONDS = 1.0


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
    parser = argparse.ArgumentParser(description=f"Appchi {role} worker")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    settings = Settings(role=role)
    health = WorkerHealth(settings.worker_health_path, role)
    health.publish()
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
        while not stopped.is_set():
            progress = 0
            failed = False
            try:
                require_clock_health(settings, cache=clock_evidence)
                transport_failed = False
                try:
                    if transport is None:
                        transport = make_transport(db, settings, profile)
                    progress = transport.turn()
                except Exception:
                    if transport is not None:
                        transport.close()
                        transport = None
                    if not transport_optional:
                        raise
                    transport_failed = True
                    log.warning("search_kafka_degraded_reconciliation_active")
                if before_turn is not None:
                    try:
                        progress += before_turn(db, settings) or 0
                    except Exception:
                        # Authority scan failure must not prevent independent
                        # Kafka hints from repairing healthy tenants.
                        if transport_failed:
                            raise
                        log.warning("search_reconciliation_degraded_hints_active")
                health.publish(ready=True)
            except Exception:
                failed = True
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:
                        pass
                    transport = None
                health.publish(ready=False)
                log.warning("worker_capability_unavailable")
                if args.once:
                    raise SystemExit(1) from None
            if args.once:
                return
            health.wait(
                stopped, 1 if failed else 0 if progress else idle_wait(transport, before_turn)
            )
    finally:
        health.publish(draining=True)
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
