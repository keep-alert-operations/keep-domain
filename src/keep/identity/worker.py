"""The manual directory refresh (``directory --once``) over ADAPI.

Requirements: REV-73; worker scope 4; identity configuration 7, 9, 12.

Coverage is split: one evidence for the user roots (looked up in batches; more
than 10,000 user roots take several) and one evidence per team root, each with
its own generation, allocated before reading, and its own 10,000-object cap. One
large or failing team cannot block the rest. A publication fenced by a newer
generation retries once; a second rejection fails those roots with
``directory_publication_incomplete``. The command reports every failed root.

Two entry points run the same ``refresh``: ``python -m keep.identity.worker --once``
(in every image that carries keep-domain, such as the Product API image) and
keep-delivery's ``python -m keep.worker directory --once``.
"""

from __future__ import annotations

import argparse
import os
import threading
from dataclasses import dataclass
from typing import Callable, Literal, Mapping, Sequence

import httpx

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
SUPERADMIN_REQUIRED = "directory_superadmin_group_required"
ADAPI_REQUIRED = "directory_adapi_configuration_required"
CONFIGURATION_INVALID = "directory_configuration_invalid"
BOOTSTRAP_ENV = "KEEP_DIRECTORY_BOOTSTRAP_QUALIFIED"


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
    """One evidence of a refresh: the user roots (a chunk) or one team root."""

    kind: Kind
    roots: tuple[str, ...]
    outcome: SaveOutcome

    @property
    def published(self) -> bool:
        return self.outcome.saved

    @property
    def reason(self) -> str | None:
        """None when published; ``directory_publication_incomplete`` when fenced twice."""
        if self.outcome.saved:
            return None
        return PUBLICATION_INCOMPLETE if self.outcome.publication.fenced else self.outcome.reason

    @property
    def evidence(self) -> DirectoryEvidence:
        return self.outcome.evidence

    @property
    def publication(self) -> PublicationResult:
        return self.outcome.publication


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
        return any(unit.publication.bootstrap_ready for unit in self.units)


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
    successful publication deletes the pending saves it covered.
    """
    source = adapi_config.source
    superadmin_group = principal_key(superadmin_group_sam, source)
    with database.transaction() as conn:
        roots = tracked_roots(conn, source, superadmin_group)
    units = []
    for kind, coverage in _units(roots, max_objects):

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
        units.append(RefreshUnit(kind, tuple(sorted(k.object_id for k in coverage)), outcome))
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


def refresh(
    database,
    settings,
    *,
    bootstrap_qualified: bool = False,
    emit: Callable[[str], None] = _print,
    stop: threading.Event | None = None,
    transport: httpx.BaseTransport | None = None,
) -> RefreshSummary:
    """One manual refresh from ``Settings``, shared by both entry points.

    Reads ``KEEP_ADAPI_URL``, ``KEEP_ADAPI_CLIENT_ID`` and ``KEEP_SUPERADMIN_GROUP``
    through ``settings``, runs ``run_cycle`` and emits ``summary_lines``. Missing
    configuration raises ``AppError`` before any ADAPI call or publication.
    """
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
    for line in summary_lines(summary):
        emit(line)
    return summary


def _connect(settings):
    from keep.db import Database

    return Database(
        settings.database_url.get_secret_value(),
        settings.pool_size,
        deployment_epoch=settings.deployment_epoch,
    )


def main(argv: Sequence[str] | None = None, *, connect: Callable | None = None) -> int:
    """``python -m keep.identity.worker --once [--bootstrap]``; returns the exit code.

    Configuration comes from the environment (``KEEP_DATABASE_URL``,
    ``KEEP_DEPLOYMENT_EPOCH``, ``KEEP_ADAPI_URL``, ``KEEP_ADAPI_CLIENT_ID``,
    ``KEEP_SUPERADMIN_GROUP``). ``--bootstrap`` or
    ``KEEP_DIRECTORY_BOOTSTRAP_QUALIFIED=true`` qualifies the refresh to open sign-in.
    Exit 0 when every root published, 1 when any root failed or the refresh could not
    run (one ``directory_refresh_failed reason=...`` line, never an error message, which
    could carry configuration values), 2 for bad arguments.
    """
    parser = argparse.ArgumentParser(
        prog="python -m keep.identity.worker",
        description="Run one ADAPI directory refresh and publication (REV-73).",
    )
    parser.add_argument(
        "--once", action="store_true", help="required: one refresh, then exit (no polling)"
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help=f"qualify this refresh to open sign-in (same as {BOOTSTRAP_ENV}=true)",
    )
    args = parser.parse_args(argv)
    if not args.once:
        parser.error("directory automation is deferred (REV-34-36); run one refresh with --once")
    from pydantic import ValidationError

    from keep.config import Settings

    try:
        settings = Settings(role="directory")
    except ValidationError:
        _print(f"directory_refresh_failed reason={CONFIGURATION_INVALID}")
        return 1
    database = None
    try:
        database = (connect or _connect)(settings)
        summary = refresh(
            database,
            settings,
            bootstrap_qualified=args.bootstrap or bootstrap_from_environment(),
        )
    except AppError as error:
        _print(f"directory_refresh_failed reason={error.code}")
        return 1
    except Exception as error:  # the message could carry a DSN or ADAPI address
        _print(f"directory_refresh_failed reason=internal_error type={type(error).__name__}")
        return 1
    finally:
        if database is not None:
            database.close()
    return 0 if summary.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
