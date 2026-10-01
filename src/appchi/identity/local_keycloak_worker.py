"""Development-only Keycloak directory publication using normal authority guards."""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from appchi.config import Settings
from appchi.db import Database

from .directory import DirectoryEvidence, DirectoryUnavailable, DirectoryVerifier, PrincipalKey
from .keycloak_directory import KeycloakDirectoryReader, load_config, require_development
from .publication import allocate_generation, publish


def run_cycle(database, config, *, bootstrap=False, transport=None):
    require_development()
    group = PrincipalKey(config.source, config.superadmin_group)
    with database.transaction() as conn:
        roots = {
            PrincipalKey(config.source, row["object_id"])
            for row in conn.execute(
                "SELECT object_id FROM principals WHERE directory_source=%s", (config.source,)
            ).fetchall()
        } | {group}
        generation = allocate_generation(conn)
    started = datetime.now(UTC)
    reader = None
    try:
        with KeycloakDirectoryReader(config, transport=transport) as reader:
            roots.update(reader.load())
            if len(roots) > config.max_objects:
                raise DirectoryUnavailable("local_directory_object_limit")
            evidence = DirectoryVerifier(reader, max_objects=config.max_objects).verify(
                roots, generation
            )
            evidence = replace(
                evidence,
                started_at=started,
                target_missed=(evidence.completed_at - started).total_seconds() > 60,
            )
    except DirectoryUnavailable:
        negatives = {
            key: obj
            for key, obj in (reader.objects.items() if reader else ())
            if not obj.eligible or obj.deleted
        }
        evidence = DirectoryEvidence(
            config.source,
            generation,
            started,
            datetime.now(UTC),
            frozenset(roots),
            negatives,
            {},
            {},
            False,
            ("local_directory_verification_incomplete",),
            negative_keys=frozenset(negatives),
        )
    with database.transaction() as conn:
        result = publish(conn, evidence, superadmin_group=group, bootstrap_qualified=bootstrap)
        if result.accepted:
            conn.execute(
                "DELETE FROM directory_verification_requests WHERE source=%s AND object_id=ANY(%s)",
                (config.source, [key.object_id for key in evidence.roots]),
            )
    return evidence, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    if not args.once:
        parser.error("directory automation is deferred; use --once for explicit publication")
    config = load_config(args.config)
    settings = Settings()
    if settings.environment != "development":
        raise ValueError("local directory worker is development only")
    database = Database(
        settings.database_url.get_secret_value(),
        size=settings.pool_size,
        deployment_epoch=settings.deployment_epoch,
    )
    try:
        while True:
            started = time.monotonic()
            evidence, result = run_cycle(database, config, bootstrap=args.bootstrap)
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
            if args.once:
                return 0 if result.accepted else 1
            time.sleep(max(0, 60 - (time.monotonic() - started)))
    finally:
        database.close()


if __name__ == "__main__":
    raise SystemExit(main())
