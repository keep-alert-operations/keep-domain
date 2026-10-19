"""Drain/fence every runtime SQL unit without changing its isolation contract."""

from contextlib import contextmanager

from appchi.shared.errors import unavailable

RESTORE_LOCK = 418003227

CONTROL_READ = "SELECT deployment_epoch,fenced FROM restore_control WHERE singleton"


def _require_current(acquired, control, deployment_epoch):
    if not acquired:
        raise unavailable("restore_in_progress")
    if not control or control["fenced"]:
        raise unavailable("restore_reconciliation_required")
    if control["deployment_epoch"] is not None and control["deployment_epoch"] != deployment_epoch:
        raise unavailable("deployment_epoch_fenced")


def queue_transaction_guard(conn):
    """Queue the guard inside a READ COMMITTED unit's setup pipeline.

    Call before the unit's first query. Restore's exclusive lock conflicts with
    this shared transaction lock exactly as with the session lock, and commit or
    rollback releases it, so no extra transactions or uncertain release exist.
    Pinned READ COMMITTED gives the control read its own snapshot, taken after
    the acquisition statement finishes (see runtime_guard). A later switch to
    REPEATABLE READ fails in PostgreSQL instead of reusing a stale control read.
    """
    conn.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
    acquisition = conn.execute(
        "SELECT pg_try_advisory_xact_lock_shared(%s) AS acquired", (RESTORE_LOCK,)
    )
    return acquisition, conn.execute(CONTROL_READ)


def require_transaction_guard(queued, deployment_epoch):
    """Check queued guard results; raising rolls back and releases the lock."""
    acquisition, control_read = queued
    _require_current(acquisition.fetchone()["acquired"], control_read.fetchone(), deployment_epoch)


@contextmanager
def runtime_guard(conn, deployment_epoch):
    acquired = False
    acquisition_started = False
    acquisition_known = False
    try:
        # Session lock spans the preliminary check and business transaction.
        # Keeping the check outside that transaction preserves caller-selected
        # REPEATABLE READ before its first domain query.
        with conn.transaction():
            # Batch network round trips, not SQL statements/snapshots. In READ
            # COMMITTED the control read must take its snapshot after acquiring
            # the session lock; combining both into one SELECT would be unsafe.
            with conn.pipeline():
                conn.execute("SET LOCAL statement_timeout = '4000ms'")
                conn.execute("SET LOCAL lock_timeout = '2000ms'")
                acquisition_started = True
                acquisition = conn.execute(
                    "SELECT pg_try_advisory_lock_shared(%s) AS acquired", (RESTORE_LOCK,)
                )
                control_read = conn.execute(CONTROL_READ)
            acquired = acquisition.fetchone()["acquired"]
            acquisition_known = True
            _require_current(acquired, control_read.fetchone(), deployment_epoch)
        yield
    finally:
        if acquired:
            try:
                with conn.transaction():
                    with conn.pipeline():
                        conn.execute("SET LOCAL statement_timeout = '4000ms'")
                        release = conn.execute(
                            "SELECT pg_advisory_unlock_shared(%s) AS released", (RESTORE_LOCK,)
                        )
                    released = release.fetchone()["released"]
                    if not released:
                        raise unavailable("restore_guard_release_unproven")
            except Exception:
                # Never return a connection holding a session lock to the pool.
                conn.close()
                raise
        elif acquisition_started and not acquisition_known:
            conn.close()
