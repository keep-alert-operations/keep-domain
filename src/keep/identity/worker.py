"""The directory refresh (``directory --once``) over ADAPI, run daily or by hand.

Requirements: REV-73; REV-75; worker scope 4; identity configuration 7, 9, 12, 13.

Coverage is split: one evidence for the user roots (looked up in batches; more
than 10,000 user roots take several) and one evidence per team root, each with
its own generation, allocated before reading, and its own 10,000-object cap. One
large or failing team cannot block the rest. A publication fenced by a newer
generation retries once; a second rejection fails those roots with
``directory_publication_incomplete``. The command reports every failed root.

Two entry points run the same ``refresh``: ``python -m keep.identity.worker --once``
(in every image that carries keep-domain, such as the Product API image, and the
command of the daily CronJob ``keep-directory-refresh``) and keep-delivery's
``python -m keep.worker directory --once``. Both log as service ``api``, role
``directory-refresh`` (REV-74, REV-75); stdout keeps its token lines.

A stop event (the run budget or SIGTERM) is checked before every ADAPI call, never
inside a publication: units not yet read fail as ``directory_stopped`` without
touching the database, and units already published stay published.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Callable, Literal, Mapping, Sequence

import httpx

from keep.observability import configure_logging, log_event, register
from keep.observability.catalog import ERROR, INFO, WARNING
from keep.shared.errors import AppError, unavailable

from .adapi import (
    MAX_OBJECTS,
    REFRESH_CALL_CAP,
    REFRESH_VERIFY_DEADLINE,
    ADAPIConfig,
    principal_key,
    verify_roots,
)
from .directory import DirectoryEvidence, PrincipalKey
from .publication import PublicationResult, SaveOutcome, publish_with_retry

Kind = Literal["user", "team"]
PUBLICATION_INCOMPLETE = "directory_publication_incomplete"
STOPPED = "directory_stopped"
SUPERADMIN_REQUIRED = "directory_superadmin_group_required"
ADAPI_REQUIRED = "directory_adapi_configuration_required"
CONFIGURATION_INVALID = "directory_configuration_invalid"
INTERNAL_ERROR = "internal_error"
BOOTSTRAP_ENV = "KEEP_DIRECTORY_BOOTSTRAP_QUALIFIED"
# REV-75: both entry points write their records to the Product API's index.
LOG_SERVICE, LOG_ROLE = "api", "directory-refresh"

log = logging.getLogger(__name__)

register(
    "directory_root_failed",
    WARNING,
    "Directory refresh could not publish {kind} roots: {reason}",
    "A unit of a directory refresh was not published: one group root (root names the "
    "group) or one batch of person roots (count says how many; their names are never "
    "logged). Those roots keep their last published state. directory_unavailable or "
    "directory_verification_deadline: check ADAPI and rerun; "
    "directory_publication_incomplete: a concurrent publication won twice, rerun; "
    "directory_group_too_large: the group exceeds 10,000 objects; directory_stopped: "
    "the run budget or SIGTERM stopped the run first.",
    required=("kind", "reason"),
    outcome="failure",
)
register(
    "directory_refresh_completed",
    INFO,
    "Directory refresh published {published} of {units} units; {failed_roots} roots failed",
    "A directory refresh finished, daily (CronJob keep-directory-refresh) or by hand. "
    "Written at warning with outcome failure when any root failed; the run then exits 1 "
    "and each failed unit has its directory_root_failed record.",
    required=("units", "published", "failed_roots", "duration"),
)
register(
    "directory_refresh_failed",
    ERROR,
    "Directory refresh could not run: {reason}",
    "The refresh stopped before or during its run: missing or invalid configuration, "
    "the database, or an unexpected error (error.type names its class; the message is "
    "never written). Nothing after the failure was published. Fix the cause and rerun.",
    required=("reason",),
    outcome="failure",
)


def tracked_roots(conn, source: str, superadmin_group: PrincipalKey) -> dict[PrincipalKey, Kind]:
    """Every root to re-read, with its stored kind (the reader's kind hint).

    Grants, live sessions (not revoked, before their absolute deadline), alert
    and incident assignees, pending saves without a failure (with their
    requested kind) and the super-admin group.
    """
    rows = conn.execute(
        """SELECT p.object_id,p.kind FROM principals p WHERE p.directory_source=%s AND (
        EXISTS(SELECT 1 FROM tenant_grants g WHERE g.principal_id=p.id)
        OR EXISTS(SELECT 1 FROM auth_sessions s WHERE s.principal_id=p.id AND s.revoked_at IS NULL
                   AND s.absolute_at>clock_timestamp())
        OR EXISTS(SELECT 1 FROM alerts a WHERE a.assignee_id=p.id))""",
        (source,),
    ).fetchall()
    roots: dict[PrincipalKey, Kind] = {
        PrincipalKey(source, row["object_id"]): row["kind"] for row in rows
    }
    if conn.execute("SELECT to_regclass('incidents') AS relation").fetchone()["relation"]:
        for row in conn.execute(
            """SELECT DISTINCT p.object_id,p.kind FROM principals p JOIN incidents i ON i.assignee_id=p.id
            WHERE p.directory_source=%s""",
            (source,),
        ).fetchall():
            roots[PrincipalKey(source, row["object_id"])] = row["kind"]
    for row in conn.execute(
        """SELECT r.object_id,COALESCE(p.kind,r.kind) AS kind FROM directory_verification_requests r
        LEFT JOIN principals p ON p.directory_source=r.source AND p.object_id=r.object_id
        WHERE r.source=%s AND r.last_failure IS NULL""",
        (source,),
    ).fetchall():
        roots.setdefault(PrincipalKey(source, row["object_id"]), row["kind"])
    roots[superadmin_group] = "team"
    return roots


@dataclass(frozen=True)
class RefreshUnit:
    """One evidence of a refresh: the user roots (a chunk) or one team root.

    ``outcome`` is None for a unit the stop event skipped before reading; such a
    unit allocated nothing and wrote nothing. ``stopped`` marks a unit that the stop
    event skipped or cut short.
    """

    kind: Kind
    roots: tuple[str, ...]
    outcome: SaveOutcome | None
    stopped: bool = False

    @property
    def published(self) -> bool:
        return self.outcome is not None and self.outcome.saved

    @property
    def reason(self) -> str | None:
        """None when published; ``directory_stopped``, or ``..._incomplete`` when fenced twice."""
        if self.published:
            return None
        if self.stopped or self.outcome is None:
            return STOPPED
        return PUBLICATION_INCOMPLETE if self.outcome.publication.fenced else self.outcome.reason

    @property
    def evidence(self) -> DirectoryEvidence | None:
        return None if self.outcome is None else self.outcome.evidence

    @property
    def publication(self) -> PublicationResult | None:
        return None if self.outcome is None else self.outcome.publication


@dataclass(frozen=True)
class RefreshSummary:
    units: tuple[RefreshUnit, ...]

    @property
    def failed(self) -> dict[str, str]:
        """Each failed root (samAccountName) and its reason."""
        return {root: unit.reason for unit in self.units if unit.reason for root in unit.roots}

    @property
    def ok(self) -> bool:
        return not self.failed

    @property
    def bootstrap_ready(self) -> bool:
        return any(
            unit.publication is not None and unit.publication.bootstrap_ready
            for unit in self.units
        )


def _units(roots: Mapping[PrincipalKey, Kind], max_objects: int):
    users = sorted(key for key, kind in roots.items() if kind == "user")
    for start in range(0, len(users), max_objects):
        yield "user", {key: "user" for key in users[start : start + max_objects]}
    for key in sorted(key for key, kind in roots.items() if kind != "user"):
        yield "team", {key: "team"}


def run_cycle(
    database,
    adapi_config: ADAPIConfig,
    superadmin_group_sam: str,
    *,
    bootstrap_qualified: bool = False,
    call_cap: float = REFRESH_CALL_CAP,
    deadline_seconds: float = REFRESH_VERIFY_DEADLINE,
    max_objects: int = MAX_OBJECTS,
    stop: threading.Event | None = None,
    transport: httpx.BaseTransport | None = None,
) -> RefreshSummary:
    """Re-read every tracked root through ADAPI and publish each unit of coverage.

    With ``bootstrap_qualified`` every unit carries the flag, but only the
    evidence covering the super-admin group can open ``human_auth``. A
    successful publication deletes the pending saves it covered. Once ``stop`` is
    set, the remaining units are skipped (REV-75); the unit being read when it was
    set fails at its next ADAPI call, and its attempt is recorded as usual.
    """
    source = adapi_config.source
    superadmin_group = principal_key(superadmin_group_sam, source)
    with database.transaction() as conn:
        roots = tracked_roots(conn, source, superadmin_group)
    units = []
    for kind, coverage in _units(roots, max_objects):
        names = tuple(sorted(k.object_id for k in coverage))
        if stop is not None and stop.is_set():
            units.append(RefreshUnit(kind, names, None, stopped=True))
            continue

        def read(generation, coverage=coverage):
            return verify_roots(
                adapi_config,
                coverage,
                generation,
                deadline_seconds=deadline_seconds,
                call_cap=call_cap,
                max_objects=max_objects,
                stop=stop,
                transport=transport,
            )

        def covered(conn, evidence):
            conn.execute(
                "DELETE FROM directory_verification_requests WHERE source=%s AND object_id=ANY(%s::text[])",
                (source, sorted(key.object_id for key in evidence.roots)),
            )

        outcome = publish_with_retry(
            database,
            read,
            superadmin_group=superadmin_group,
            bootstrap_qualified=bootstrap_qualified,
            on_accepted=covered,
        )
        # A read cut short by the stop reports the stop, not an ADAPI outage.
        stopped = bool(
            stop is not None
            and stop.is_set()
            and not outcome.saved
            and not outcome.publication.fenced
        )
        units.append(RefreshUnit(kind, names, outcome, stopped=stopped))
    return RefreshSummary(tuple(units))


def bootstrap_from_environment(environ: Mapping[str, str] | None = None) -> bool:
    """``KEEP_DIRECTORY_BOOTSTRAP_QUALIFIED``: only the exact value ``true`` qualifies."""
    return (os.environ if environ is None else environ).get(BOOTSTRAP_ENV) == "true"


def summary_lines(summary: RefreshSummary) -> list[str]:
    """One line per failed root, then a totals line; names and reasons only, no secrets."""
    lines = [
        f"directory_root_failed root={root} reason={reason}"
        for root, reason in sorted(summary.failed.items())
    ]
    published = sum(1 for unit in summary.units if unit.published)
    lines.append(
        f"directory_refresh units={len(summary.units)} published={published} "
        f"failed_roots={len(summary.failed)} "
        f"bootstrap_ready={'true' if summary.bootstrap_ready else 'false'}"
    )
    return lines


def _print(line: str) -> None:
    print(line, flush=True)


def configure_refresh_logging() -> None:
    """REV-74 logging for a refresh process: service ``api``, role ``directory-refresh``."""
    configure_logging(LOG_SERVICE, role=LOG_ROLE)


def _error_class(error: BaseException) -> str:
    kind = type(error)
    return f"{kind.__module__}.{kind.__qualname__}"


def log_refresh_failed(reason: str, error: BaseException | None = None) -> None:
    """``directory_refresh_failed``: the reason and the error's class, never its message."""
    log_event(
        log,
        "directory_refresh_failed",
        reason=reason,
        error_class=None if error is None else _error_class(error),
    )


def _log_summary(summary: RefreshSummary, seconds: float) -> None:
    """One record per failed unit, then the totals (observability 4: no person's name)."""
    for unit in summary.units:
        if unit.reason is None:
            continue
        if unit.kind == "team":
            log_event(log, "directory_root_failed", kind="team", root=unit.roots[0],
                      reason=unit.reason)
        else:
            log_event(log, "directory_root_failed", kind="user", count=len(unit.roots),
                      reason=unit.reason)
    log_event(
        log,
        "directory_refresh_completed",
        level=INFO if summary.ok else WARNING,
        ok=summary.ok,
        units=len(summary.units),
        published=sum(1 for unit in summary.units if unit.published),
        failed_roots=len(summary.failed),
        duration=seconds,
    )


def refresh(
    database,
    settings,
    *,
    bootstrap_qualified: bool = False,
    emit: Callable[[str], None] = _print,
    stop: threading.Event | None = None,
    transport: httpx.BaseTransport | None = None,
) -> RefreshSummary:
    """One refresh from ``Settings``, shared by both entry points.

    Reads ``KEEP_ADAPI_URL``, ``KEEP_ADAPI_CLIENT_ID`` and ``KEEP_SUPERADMIN_GROUP``
    through ``settings``, runs ``run_cycle``, emits ``summary_lines`` and writes the
    REV-75 records. Missing configuration raises ``AppError`` before any ADAPI call
    or publication; any failure is recorded as ``directory_refresh_failed`` and
    raised again for the entry point to report.
    """
    started = time.monotonic()
    try:
        if not settings.superadmin_group:
            raise unavailable(SUPERADMIN_REQUIRED)
        if not settings.adapi_url or settings.adapi_client_id is None:
            raise unavailable(ADAPI_REQUIRED)
        summary = run_cycle(
            database,
            ADAPIConfig.from_settings(settings),
            settings.superadmin_group,
            bootstrap_qualified=bootstrap_qualified,
            stop=stop,
            transport=transport,
        )
    except AppError as error:
        log_refresh_failed(error.code, error)
        raise
    except Exception as error:  # the message could carry a DSN or ADAPI address
        log_refresh_failed(INTERNAL_ERROR, error)
        raise
    for line in summary_lines(summary):
        emit(line)
    _log_summary(summary, time.monotonic() - started)
    return summary


def _connect(settings):
    from keep.db import Database

    return Database(
        settings.database_url.get_secret_value(),
        settings.pool_size,
        deployment_epoch=settings.deployment_epoch,
    )


def stop_on_signal(stop: threading.Event) -> Callable:
    """A signal handler that only sets ``stop``; the refresh finishes what it publishes."""

    def handler(signum, frame) -> None:
        stop.set()

    return handler


def _budget(value: str) -> float:
    seconds = float(value)
    if not 0 < seconds < float("inf"):
        raise argparse.ArgumentTypeError("the budget must be a positive number of seconds")
    return seconds


def _flush_logs() -> None:
    # A short-lived process: hand queued records to the shipper before exiting.
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:
            pass


def main(
    argv: Sequence[str] | None = None,
    *,
    connect: Callable | None = None,
    transport: httpx.BaseTransport | None = None,
) -> int:
    """``python -m keep.identity.worker --once [--bootstrap] [--budget-seconds N]``.

    Returns the exit code. Configuration comes from the environment
    (``KEEP_DATABASE_URL``, ``KEEP_DEPLOYMENT_EPOCH``, ``KEEP_ADAPI_URL``,
    ``KEEP_ADAPI_CLIENT_ID``, ``KEEP_SUPERADMIN_GROUP``). ``--bootstrap`` or
    ``KEEP_DIRECTORY_BOOTSTRAP_QUALIFIED=true`` qualifies the refresh to open sign-in.
    ``--budget-seconds`` (the daily CronJob passes 1,800) and SIGTERM set the stop
    event; without a budget a manual run is unbounded. Exit 0 when every root
    published, 1 when any root failed or stopped, or the refresh could not run (one
    ``directory_refresh_failed reason=...`` line, never an error message, which could
    carry configuration values), 2 for bad arguments. ``transport`` is for tests.
    """
    parser = argparse.ArgumentParser(
        prog="python -m keep.identity.worker",
        description="Run one ADAPI directory refresh and publication (REV-73, REV-75).",
    )
    parser.add_argument(
        "--once", action="store_true", help="required: one refresh, then exit (no polling)"
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help=f"qualify this refresh to open sign-in (same as {BOOTSTRAP_ENV}=true)",
    )
    parser.add_argument(
        "--budget-seconds",
        type=_budget,
        default=None,
        help="stop reading ADAPI after this many seconds; unread roots fail as directory_stopped",
    )
    args = parser.parse_args(argv)
    if not args.once:
        parser.error("directory automation is deferred (REV-34-36); run one refresh with --once")
    from pydantic import ValidationError

    from keep.config import Settings

    configure_refresh_logging()
    stop = threading.Event()
    timer = None
    previous = None
    if threading.current_thread() is threading.main_thread():
        previous = signal.signal(signal.SIGTERM, stop_on_signal(stop))
    if args.budget_seconds is not None:
        timer = threading.Timer(args.budget_seconds, stop.set)
        timer.daemon = True
        timer.start()
    database = None
    try:
        try:
            settings = Settings(role="directory")
        except ValidationError as error:
            log_refresh_failed(CONFIGURATION_INVALID, error)
            _print(f"directory_refresh_failed reason={CONFIGURATION_INVALID}")
            return 1
        try:
            database = (connect or _connect)(settings)
        except Exception as error:  # the message could carry a DSN
            log_refresh_failed(INTERNAL_ERROR, error)
            _print(f"directory_refresh_failed reason={INTERNAL_ERROR} type={type(error).__name__}")
            return 1
        try:
            summary = refresh(
                database,
                settings,
                bootstrap_qualified=args.bootstrap or bootstrap_from_environment(),
                stop=stop,
                transport=transport,
            )
        except AppError as error:  # refresh() recorded it
            _print(f"directory_refresh_failed reason={error.code}")
            return 1
        except Exception as error:  # the message could carry a DSN or ADAPI address
            _print(f"directory_refresh_failed reason={INTERNAL_ERROR} type={type(error).__name__}")
            return 1
        return 0 if summary.ok else 1
    finally:
        if timer is not None:
            timer.cancel()
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)
        if database is not None:
            database.close()
        _flush_logs()


if __name__ == "__main__":
    raise SystemExit(main())
