"""Drain/fence every runtime SQL unit without changing its isolation contract."""

from contextlib import contextmanager

from appchi.shared.errors import unavailable

RESTORE_LOCK = 418003227


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
            conn.execute("SET LOCAL statement_timeout = '4000ms'")
            conn.execute("SET LOCAL lock_timeout = '2000ms'")
            acquisition_started = True
            acquired = conn.execute(
                "SELECT pg_try_advisory_lock_shared(%s) AS acquired", (RESTORE_LOCK,)
            ).fetchone()["acquired"]
            acquisition_known = True
            if not acquired:
                raise unavailable("restore_in_progress")
            control = conn.execute(
                "SELECT deployment_epoch,fenced FROM restore_control WHERE singleton"
            ).fetchone()
            if not control or control["fenced"]:
                raise unavailable("restore_reconciliation_required")
            if (
                control["deployment_epoch"] is not None
                and control["deployment_epoch"] != deployment_epoch
            ):
                raise unavailable("deployment_epoch_fenced")
        yield
    finally:
        if acquired:
            try:
                with conn.transaction():
                    conn.execute("SET LOCAL statement_timeout = '4000ms'")
                    released = conn.execute(
                        "SELECT pg_advisory_unlock_shared(%s) AS released", (RESTORE_LOCK,)
                    ).fetchone()["released"]
                    if not released:
                        raise unavailable("restore_guard_release_unproven")
            except Exception:
                # Never return a connection holding a session lock to the pool.
                conn.close()
                raise
        elif acquisition_started and not acquisition_known:
            conn.close()
