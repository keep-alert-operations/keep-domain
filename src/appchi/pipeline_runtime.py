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
            health.wait(stopped, 1 if failed else 0 if progress else 0.01)
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
