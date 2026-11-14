"""Directory-worker entry points with explicit private-deployment bindings."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .directory import DirectoryEvidence, DirectoryUnavailable, DirectoryVerifier, PrincipalKey
from .ldap import LDAPConfig, LDAPDirectoryReader, LDAPSchema
from .publication import allocate_generation, publish


def load_directory_config(path: Path) -> LDAPConfig:
    """Read sanitized schema/trust configuration; password only from named env.

    The configuration document contains LDAPConfig fields except password, plus
    password_env identifying a secret-injected variable and schema's exact fields.
    Unknown fields raise; no directory vendor or company schema is inferred.
    """
    if path.stat().st_size > 65536:
        raise ValueError("directory configuration exceeds its size limit")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or "password" in document:
        raise ValueError("directory password must use an injected secret environment variable")
    password_env = document.pop("password_env")
    if not isinstance(password_env, str) or not password_env or password_env not in os.environ:
        raise ValueError("directory password environment binding is missing")
    schema = document.pop("schema")
    if not isinstance(schema, dict):
        raise ValueError("explicit directory schema is required")
    if "eligibility_values" in schema:
        schema["eligibility_values"] = tuple(schema["eligibility_values"])
    return LDAPConfig(**document, password=os.environ[password_env], schema=LDAPSchema(**schema))


def tracked_roots(conn, source: str, superadmin_group: PrincipalKey) -> frozenset[PrincipalKey]:
    rows = conn.execute(
        """SELECT DISTINCT p.object_id FROM principals p WHERE p.directory_source=%s AND (
        EXISTS(SELECT 1 FROM tenant_grants g WHERE g.principal_id=p.id)
        OR EXISTS(SELECT 1 FROM auth_sessions s WHERE s.principal_id=p.id AND s.revoked_at IS NULL
                   AND s.absolute_at>clock_timestamp() AND s.activity_at>clock_timestamp()-interval '30 minutes')
        OR EXISTS(SELECT 1 FROM alerts a WHERE a.assignee_id=p.id))""",
        (source,),
    ).fetchall()
    roots = {PrincipalKey(source, row["object_id"]) for row in rows}
    if conn.execute("SELECT to_regclass('incidents') AS relation").fetchone()["relation"]:
        incident_users = conn.execute(
            """SELECT DISTINCT p.object_id FROM principals p JOIN incidents i ON i.assignee_id=p.id
                                       WHERE p.directory_source=%s""",
            (source,),
        ).fetchall()
        roots.update(PrincipalKey(source, row["object_id"]) for row in incident_users)
    requests = conn.execute(
        "SELECT object_id FROM directory_verification_requests WHERE source=%s", (source,)
    ).fetchall()
    roots.update(PrincipalKey(source, row["object_id"]) for row in requests)
    roots.add(superadmin_group)
    return frozenset(roots)


def run_cycle(
    database,
    config: LDAPConfig,
    superadmin_group: PrincipalKey,
    *,
    bootstrap_qualified: bool = False,
):
    if config.source != superadmin_group.source:
        raise ValueError("directory source mismatch")
    if bootstrap_qualified and not config.schema.schema_qualified:
        raise ValueError("bootstrap requires qualified directory schema and complete visibility")
    with database.transaction() as conn:
        roots = tracked_roots(conn, config.source, superadmin_group)
        generation = allocate_generation(conn)
    started = datetime.now(UTC)
    try:
        with LDAPDirectoryReader(config) as reader:
            evidence = DirectoryVerifier(reader, max_objects=config.max_objects).verify(
                roots, generation
            )
    except DirectoryUnavailable:
        evidence = DirectoryEvidence(
            config.source,
            generation,
            started,
            datetime.now(UTC),
            roots,
            {},
            {},
            {},
            False,
            ("directory_connection_unavailable",),
        )
    with database.transaction() as conn:
        result = publish(
            conn,
            evidence,
            superadmin_group=superadmin_group,
            bootstrap_qualified=bootstrap_qualified,
        )
        if result.accepted:
            conn.execute(
                "DELETE FROM directory_verification_requests WHERE source=%s AND object_id=ANY(%s)",
                (config.source, [key.object_id for key in evidence.roots]),
            )
        # Token destruction follows actual local deadlines/revocation, never
        # directory-data age. No cached identity eviction during refresh failure.
        conn.execute("""UPDATE auth_sessions SET tokens=NULL WHERE tokens IS NOT NULL AND
                     (revoked_at IS NOT NULL OR absolute_at<=clock_timestamp()
                      OR activity_at<=clock_timestamp()-interval '30 minutes')""")
        conn.execute("DELETE FROM login_transactions WHERE expires_at<=clock_timestamp()")
        conn.execute("DELETE FROM logout_fences WHERE expires_at<=clock_timestamp()")
    return evidence, result


def main() -> int:
    """Explicit one-shot LDAP directory publication.

    REV-35 keeps directory automation deferred: this command performs a single
    trusted publication cycle (optionally lifting the initial bootstrap gate) and
    starts no polling worker. It uses the same guarded publication path as the
    scheduled `run_cycle`. The superadmin group id is supplied through
    KEEP_SUPERADMIN_GROUP and bound to the configuration's directory source.
    """
    import argparse

    from keep.config import Settings
    from keep.db import Database

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    if not args.once:
        parser.error("directory automation is deferred; use --once for explicit publication")
    config = load_directory_config(args.config)
    settings = Settings()
    if not settings.superadmin_group:
        raise ValueError("KEEP_SUPERADMIN_GROUP is required for directory publication")
    database = Database(
        settings.database_url.get_secret_value(),
        size=settings.pool_size,
        deployment_epoch=settings.deployment_epoch,
    )
    try:
        evidence, result = run_cycle(
            database,
            config,
            PrincipalKey(config.source, settings.superadmin_group),
            bootstrap_qualified=args.bootstrap,
        )
        print(
            json.dumps(
                {
                    "complete": evidence.complete,
                    "accepted": result.accepted,
                    "generation": evidence.generation,
                    "objects": len(evidence.objects),
                    "semantic_revision": result.semantic_revision,
                    "bootstrap_ready": result.bootstrap_ready,
                }
            ),
            flush=True,
        )
        return 0 if result.accepted else 1
    finally:
        database.close()


if __name__ == "__main__":
    raise SystemExit(main())
