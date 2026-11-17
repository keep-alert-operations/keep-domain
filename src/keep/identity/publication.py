"""Atomic directory checkpoint publication.

Requirements: REV-73; REV-76; identity configuration 7-8, 12; worker scope 4.

REV-76: Keep does not track disabled or deleted people. A person ADAPI does not
find is never stored, tombstoned or negated, and no publication ends a session.
A group that is not found is still tombstoned.

Run with a trusted database identity: the refresh command, or the Product API for
sign-in and save on pick. Network traversal must finish before opening the
publishing transaction. The caller owns the commit boundary.

Lock order for API callers: take the exclusive identity guard first, then
authorize, then publish in the same transaction. ``publish()`` takes the same
guard ``FOR UPDATE`` again, which PostgreSQL grants to the transaction that
already holds it. Statements under the guard are set-based, so a 10,000-object
publication holds it well under a second.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Callable

from psycopg.types.json import Jsonb

from .directory import (
    FAILURE_BUSY,
    FAILURE_UNAVAILABLE,
    DirectoryEvidence,
    DirectoryObject,
    PrincipalKey,
)


@dataclass(frozen=True)
class PublicationResult:
    accepted: bool
    semantic_revision: int
    changed_access: tuple[tuple[str, str], ...]
    bootstrap_ready: bool
    # Complete evidence refused because a covered root or team already holds an
    # equal or newer generation; the caller may retry once with a new generation.
    fenced: bool = False


def allocate_generation(conn) -> int:
    return conn.execute("SELECT nextval('directory_generation_seq') AS generation").fetchone()[
        "generation"
    ]


def lock_identity(conn) -> None:
    """Take the exclusive identity guard (first, before authorizing a publication)."""
    conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR UPDATE")


def _key_order(key: PrincipalKey) -> tuple[str, str]:
    """PrincipalKey's own (dataclass) order, as a cheap sort key."""
    return key.source, key.object_id


def _audit_many(conn, events) -> None:
    """Insert ``(tenant, kind, evidence)`` audit events in one statement, in order.

    The events travel as one JSON array (a 5,000-event republication would
    otherwise spend most of its time adapting four parameter arrays); ids come
    from the column default.
    """
    if not events:
        return
    conn.execute(
        """INSERT INTO audit_events(tenant_id,actor_id,actor_label,kind,evidence)
        SELECT (e.value->>0)::uuid,NULL,'directory-synchronizer',e.value->>1,e.value->2
        FROM jsonb_array_elements(%s::jsonb) WITH ORDINALITY AS e(value,position)
        ORDER BY e.position""",
        (
            json.dumps(
                [
                    [str(tenant) if tenant else None, kind, evidence]
                    for tenant, kind, evidence in events
                ],
                separators=(",", ":"),
            ),
        ),
    )


def _local_roles(conn):
    """Each eligible user's best local role per tenant, from direct and team grants.

    A grant reaches a user directly or through a membership of the granted team.
    Written as a union of the two (not one join with an OR) so the plan stays
    linear in grants plus memberships; the OR form compared every grant with
    every user and its cost estimate crossed the JIT threshold at 10,000 users.
    Text ids: comparing and auditing them needs no UUID objects.
    """
    rows = conn.execute("""SELECT a.tenant_id::text AS tenant_id,p.id::text AS user_id, max(CASE a.role WHEN 'admin' THEN 3 WHEN 'edit' THEN 2 ELSE 1 END) AS role
        FROM (SELECT g.tenant_id,g.role,g.principal_id AS user_id FROM tenant_grants g
          UNION ALL
          SELECT g.tenant_id,g.role,m.user_id FROM tenant_grants g
          JOIN directory_memberships m ON m.team_id=g.principal_id) a
        JOIN principals p ON p.id=a.user_id AND p.eligible AND NOT p.deleted AND p.kind='user'
        GROUP BY a.tenant_id,p.id""").fetchall()
    return {(row["tenant_id"], row["user_id"]): row["role"] for row in rows}


def _rebuild_memberships(conn) -> bool:
    """Make memberships equal what checkpoints, edges and eligibility derive.

    Cycle-safe recursive UNION (not UNION ALL) preserves alternate paths and
    excludes verified deleted/disabled intermediates. Sources never cross. Only
    the difference is written; returns whether anything changed.
    """
    row = conn.execute("""WITH RECURSIVE reachable(team_id,member_id) AS (
        SELECT r.root_id,e.child_id FROM directory_root_checkpoints r
        JOIN principals p ON p.id=r.root_id AND p.kind='team' AND p.eligible AND NOT p.deleted
        JOIN directory_edges e ON e.parent_id=r.root_id
        UNION
        SELECT r.team_id,e.child_id FROM reachable r
        JOIN principals p ON p.id=r.member_id AND p.kind='team' AND p.eligible AND NOT p.deleted
        JOIN directory_edges e ON e.parent_id=r.member_id),
      desired AS (
        SELECT DISTINCT r.team_id,r.member_id AS user_id FROM reachable r JOIN principals p ON p.id=r.member_id
        WHERE p.kind='user' AND p.eligible AND NOT p.deleted),
      removed AS (
        DELETE FROM directory_memberships m WHERE NOT EXISTS(
          SELECT 1 FROM desired d WHERE d.team_id=m.team_id AND d.user_id=m.user_id)
        RETURNING 1),
      added AS (
        INSERT INTO directory_memberships(team_id,user_id)
        SELECT d.team_id,d.user_id FROM desired d WHERE NOT EXISTS(
          SELECT 1 FROM directory_memberships m WHERE m.team_id=d.team_id AND m.user_id=d.user_id)
        RETURNING 1)
      SELECT (SELECT count(*) FROM removed) AS removed,(SELECT count(*) FROM added) AS added""").fetchone()
    return bool(row["removed"] or row["added"])


def stored_matches(conn, obj: DirectoryObject) -> bool:
    """Whether a verified stored principal already says what ``obj`` says.

    Sign-in publishes the person's row only when this is false (new, renamed, or
    stored ineligible or deleted by an earlier version), so routine sign-ins
    publish nothing.
    """
    row = conn.execute(
        """SELECT kind,display_name,eligible,deleted,evidence_generation,verified_at
        FROM principals WHERE directory_source=%s AND object_id=%s""",
        (obj.key.source, obj.key.object_id),
    ).fetchone()
    return bool(
        row
        and row["verified_at"] is not None
        and row["evidence_generation"] >= 1
        and (row["kind"], row["display_name"], row["eligible"], row["deleted"])
        == (obj.kind, obj.label, obj.eligible, obj.deleted)
    )


def publish(
    conn,
    evidence: DirectoryEvidence,
    *,
    superadmin_group: PrincipalKey,
    bootstrap_qualified: bool = False,
) -> PublicationResult:
    """Publish full evidence or independently verified negative facts only.

    Negative facts are groups not found (REV-76). A person not found is skipped:
    no principal row, edge or checkpoint is written for them.

    Narrower fence (REV-73): complete evidence is refused (``fenced``) only when a
    covered root or team already holds an equal or newer generation. A covered
    user leaf that a newer generation already holds is skipped; the group's edges
    still publish and memberships are rebuilt from stored eligibility, so the
    newer fact wins.

    bootstrap_qualified is supplied by the controlled configuration/qualification
    command, never a browser request. It opens human_auth only from evidence
    whose roots include the super-admin group (split coverage: the user-root
    evidence never opens it). It cannot compensate for empty/incomplete group
    evidence. Ordinary refresh cannot lift a restore-integrity gate.
    """
    if superadmin_group.source != evidence.source:
        raise ValueError("superadmin group and directory evidence source must match")
    # Prepare everything that needs no database before taking the guard.
    digest = evidence.semantic_digest if evidence.complete else None
    coverage_roots = sorted(k.object_id for k in evidence.roots)
    coverage_objects = sorted(k.object_id for k in evidence.objects)
    # Edges may name stored principals the evidence does not carry as objects.
    named = (
        set(evidence.objects)
        | evidence.roots
        | set(evidence.edges)
        | {child for children in evidence.edges.values() for child in children}
        | {superadmin_group}
    )
    keys = sorted({k.object_id for k in named})
    lock_identity(conn)
    previous = conn.execute(
        "SELECT COALESCE(max(semantic_revision),0) AS revision FROM directory_verifications"
    ).fetchone()["revision"]
    if conn.execute(
        "SELECT 1 FROM directory_verifications WHERE generation=%s", (evidence.generation,)
    ).fetchone():
        return PublicationResult(False, previous, (), False)
    before_roles = _local_roles(conn)
    before_admins = {tenant for (tenant, _), role in before_roles.items() if role == 3}
    # Under the guard, every statement adapts as little as possible: text ids, the
    # columns this function reads, and binary (%b) parameter arrays.
    stored_rows = {
        row["object_id"]: row
        for row in conn.execute(
            """SELECT id::text AS id,object_id,kind,display_name,eligible,deleted,evidence_generation
            FROM principals WHERE directory_source=%s AND object_id=ANY(%b::text[])""",
            (evidence.source, keys),
        ).fetchall()
    }
    current = {
        key: stored_rows[key.object_id]
        for key in named
        if key.source == evidence.source and key.object_id in stored_rows
    }

    def newer(key):
        old = current.get(key)
        return old is not None and old["evidence_generation"] >= evidence.generation

    governing = set(evidence.roots) | {
        key
        for key, obj in evidence.objects.items()
        if obj.kind == "team" or current.get(key, {}).get("kind") == "team"
    }
    # REV-76: a person not found contributes nothing (judged by the stored kind,
    # so a stored group that is gone is still tombstoned).
    missing = {
        key
        for key, obj in evidence.objects.items()
        if obj.deleted and (current[key]["kind"] if key in current else obj.kind) == "user"
    }
    fenced = evidence.complete and any(newer(key) for key in governing)
    accepted = evidence.complete and not fenced
    applicable = (
        evidence.objects if accepted else {k: evidence.objects[k] for k in evidence.negative_keys}
    )
    changed = False
    rows = []
    for key, obj in sorted(applicable.items(), key=lambda item: _key_order(item[0])):
        if newer(key) or key in missing:
            continue
        old = current.get(key)
        # A missing group's tombstone must retain its previously known type.
        kind = old["kind"] if old and obj.deleted else obj.kind
        values = (kind, obj.label, obj.eligible, obj.deleted)
        if old is None or values != (
            old["kind"],
            old["display_name"],
            old["eligible"],
            old["deleted"],
        ):
            changed = True
        rows.append((key, *values))
    stored = [row for row in rows if row[0] in current]
    if stored:
        # One statement for every known principal; the stored row is otherwise known.
        conn.execute(
            """UPDATE principals p SET kind=t.kind,display_name=t.display_name,eligible=t.eligible,
            deleted=t.deleted,evidence_generation=%s,verified_at=%s
            FROM unnest(%b::uuid[],%b::text[],%b::text[],%b::boolean[],%b::boolean[])
              AS t(id,kind,display_name,eligible,deleted)
            WHERE p.id=t.id AND p.evidence_generation<%s""",
            (
                evidence.generation,
                evidence.completed_at,
                [current[row[0]]["id"] for row in stored],
                *(list(column) for column in list(zip(*stored))[1:]),
                evidence.generation,
            ),
        )
        for key, kind, label, eligible, deleted in stored:
            current[key].update(
                kind=kind,
                display_name=label,
                eligible=eligible,
                deleted=deleted,
                evidence_generation=evidence.generation,
            )
    fresh = [row for row in rows if row[0] not in current]
    if fresh:
        fresh_keys = {row[0].object_id: row[0] for row in fresh}
        for row in conn.execute(
            """INSERT INTO principals(directory_source,object_id,kind,display_name,eligible,deleted,evidence_generation,verified_at)
            SELECT %s,t.object_id,t.kind,t.display_name,t.eligible,t.deleted,%s,%s
            FROM unnest(%b::text[],%b::text[],%b::text[],%b::boolean[],%b::boolean[])
              AS t(object_id,kind,display_name,eligible,deleted)
            RETURNING id::text AS id,object_id,kind,display_name,eligible,deleted,evidence_generation""",
            (
                evidence.source,
                evidence.generation,
                evidence.completed_at,
                [row[0].object_id for row in fresh],
                *(list(column) for column in list(zip(*fresh))[1:]),
            ),
        ).fetchall():
            current[fresh_keys[row["object_id"]]] = row
    if accepted:
        parents = [current[key]["id"] for key in sorted(evidence.edges, key=_key_order)]
        desired = {
            (current[key]["id"], current[child]["id"])
            for key, children in evidence.edges.items()
            for child in children
            if child not in missing
        }
        existing = {
            (row["parent_id"], row["child_id"])
            for row in conn.execute(
                """SELECT parent_id::text AS parent_id,child_id::text AS child_id
                FROM directory_edges WHERE parent_id=ANY(%b::uuid[])""",
                (parents,),
            ).fetchall()
        }
        # Canonical lowercase text ids sort as their UUIDs do.
        removed, added = sorted(existing - desired), sorted(desired - existing)
        if removed:
            conn.execute(
                """DELETE FROM directory_edges e USING unnest(%b::uuid[],%b::uuid[]) AS d(parent_id,child_id)
                WHERE e.parent_id=d.parent_id AND e.child_id=d.child_id""",
                ([p for p, _ in removed], [c for _, c in removed]),
            )
        if added:
            conn.execute(
                """INSERT INTO directory_edges(parent_id,child_id)
                SELECT * FROM unnest(%b::uuid[],%b::uuid[])""",
                ([p for p, _ in added], [c for _, c in added]),
            )
        changed = changed or bool(removed or added)
        conn.execute(
            """INSERT INTO directory_root_checkpoints(root_id,generation,verified_at,semantic_digest)
            SELECT r.root_id,%s,%s,%s FROM unnest(%b::uuid[]) AS r(root_id)
            ON CONFLICT(root_id) DO UPDATE SET generation=EXCLUDED.generation,
            verified_at=EXCLUDED.verified_at,semantic_digest=EXCLUDED.semantic_digest
            WHERE directory_root_checkpoints.generation<EXCLUDED.generation""",
            (
                evidence.generation,
                evidence.completed_at,
                digest,
                [
                    current[key]["id"]
                    for key in sorted(evidence.roots, key=_key_order)
                    if key not in missing
                ],
            ),
        )
    revision = previous + int(changed)
    conn.execute(
        """INSERT INTO directory_verifications(generation,source,started_at,completed_at,complete,semantic_revision,coverage,failures,target_missed)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            evidence.generation,
            evidence.source,
            evidence.started_at,
            evidence.completed_at,
            evidence.complete,
            revision,
            Jsonb(
                {
                    "roots": coverage_roots,
                    "objects": coverage_objects,
                    "accepted": accepted,
                    "fenced": fenced,
                }
            ),
            Jsonb(list(evidence.failures)),
            evidence.target_missed,
        ),
    )
    if not accepted and not applicable:
        return PublicationResult(False, revision, (), False, fenced)
    # Content revision may stay unchanged while a newly tracked root or changed
    # configured admin mapping changes derived authority. Fence every derivation,
    # including away-and-back changes, independently of semantic cursor revision.
    conn.execute(
        "UPDATE authorization_guards SET directory_revision=directory_revision+1 WHERE scope='identity'"
    )
    membership_changed = _rebuild_memberships(conn)
    group = current.get(superadmin_group)
    group_id = group["id"] if group else None
    global_before = {
        str(r["id"]) for r in conn.execute("SELECT id FROM principals WHERE super_admin").fetchall()
    }
    global_after = (
        {
            str(r["user_id"])
            for r in conn.execute(
                "SELECT user_id FROM directory_memberships WHERE team_id=%s", (group_id,)
            ).fetchall()
        }
        if group and group["kind"] == "team" and group["eligible"] and not group["deleted"]
        else set()
    )
    # Never infer an unknown replacement mapping. An existing checkpoint or this
    # accepted complete root is needed before deriving its privilege.
    global_changes = set()
    if (
        group
        and conn.execute(
            "SELECT 1 FROM directory_root_checkpoints WHERE root_id=%s", (group_id,)
        ).fetchone()
    ):
        global_changes = global_before ^ global_after
        if global_changes:
            conn.execute(
                "UPDATE principals SET super_admin=NOT super_admin WHERE id=ANY(%s::uuid[])",
                (sorted(global_changes),),
            )
    # Tracking an already-known root or switching the configured admin mapping
    # can change derived content without changing any object/edge. Finalize the
    # same transaction's checkpoint before emitting revision-bound audit events.
    if not changed and (membership_changed or global_changes):
        revision += 1
        conn.execute(
            "UPDATE directory_verifications SET semantic_revision=%s WHERE generation=%s",
            (revision, evidence.generation),
        )
    events = [
        (
            None,
            "global_privilege_changed",
            {
                "principal_id": principal,
                "before": principal in global_before,
                "after": principal in global_after,
                "generation": evidence.generation,
                "semantic_revision": revision,
            },
        )
        for principal in sorted(global_changes)
    ]
    after_roles = _local_roles(conn)
    changed_access = tuple(
        sorted(
            key
            for key in before_roles.keys() | after_roles.keys()
            if before_roles.get(key) != after_roles.get(key)
        )
    )
    events.extend(
        (
            tenant,
            "directory_access_changed",
            {
                "principal_id": principal,
                "before": before_roles.get((tenant, principal)),
                "after": after_roles.get((tenant, principal)),
                "generation": evidence.generation,
                "semantic_revision": revision,
            },
        )
        for tenant, principal in changed_access
    )
    after_admins = {tenant for (tenant, _), role in after_roles.items() if role == 3}
    events.extend(
        (
            tenant,
            "local_admin_restored" if tenant in after_admins else "local_admin_vacancy",
            {"generation": evidence.generation, "semantic_revision": revision},
        )
        for tenant in sorted(before_admins ^ after_admins)
    )
    if previous == 0 and accepted:
        events.append(
            (
                None,
                "directory_baseline_established",
                {"generation": evidence.generation, "source": evidence.source},
            )
        )
    _audit_many(conn, events)
    ready = bool(
        accepted and superadmin_group in evidence.roots and global_after and bootstrap_qualified
    )
    if ready:
        # Only initial bootstrap; restore and independently raised integrity
        # gates need their dedicated reconciliation proof and cannot be lifted.
        conn.execute("""UPDATE capability_gates SET ready=true,reason='directory_bootstrap_verified'
                     WHERE capability='human_auth' AND ready=false AND reason='directory_bootstrap_required'""")
    return PublicationResult(accepted, revision, changed_access, ready, fenced)


@dataclass(frozen=True)
class SaveOutcome:
    """The last attempt of ``publish_with_retry``.

    ``reason`` is None when published, else a structured failure: the evidence's
    own (``directory_unavailable``, ``directory_group_too_large``,
    ``directory_verification_deadline``) or ``directory_busy`` when every attempt
    was fenced (``publication.fenced`` is then true).
    """

    evidence: DirectoryEvidence
    publication: PublicationResult
    reason: str | None
    attempts: int
    # Wall time from the first allocation to the last commit.
    elapsed_seconds: float = 0.0

    @property
    def saved(self) -> bool:
        return self.reason is None


def publish_with_retry(
    database,
    read: Callable[[int], DirectoryEvidence],
    *,
    superadmin_group: PrincipalKey,
    bootstrap_qualified: bool = False,
    authorize: Callable[[object], None] | None = None,
    on_accepted: Callable[[object, DirectoryEvidence], None] | None = None,
    attempts: int = 2,
    retry_allowed: Callable[[], bool] | None = None,
) -> SaveOutcome:
    """Allocate, read, publish; retry once with a new generation when fenced.

    Each attempt allocates its generation before ``read(generation)`` runs, and
    ``read`` holds no database connection (it returns incomplete evidence rather
    than raising for directory failures). The publishing transaction takes the
    exclusive identity guard first, then calls ``authorize(conn)`` (which may
    raise to publish nothing), then ``publish()``, then, if accepted,
    ``on_accepted(conn, evidence)`` in the same transaction. ``retry_allowed``
    (for example, enough request budget left) gates the second attempt.
    """
    if attempts < 1:
        raise ValueError("at least one publication attempt is required")
    started = time.monotonic()
    for attempt in range(1, attempts + 1):
        with database.transaction() as conn:
            generation = allocate_generation(conn)
        evidence = read(generation)
        if evidence.generation != generation:
            raise ValueError("evidence must carry the allocated generation")
        with database.transaction() as conn:
            lock_identity(conn)
            if authorize is not None:
                authorize(conn)
            result = publish(
                conn,
                evidence,
                superadmin_group=superadmin_group,
                bootstrap_qualified=bootstrap_qualified,
            )
            if result.accepted and on_accepted is not None:
                on_accepted(conn, evidence)
        elapsed = time.monotonic() - started
        if result.accepted:
            return SaveOutcome(evidence, result, None, attempt, elapsed)
        if not result.fenced:
            reason = evidence.failure_reason or FAILURE_UNAVAILABLE
            return SaveOutcome(evidence, result, reason, attempt, elapsed)
        if attempt == attempts or (retry_allowed is not None and not retry_allowed()):
            break
    return SaveOutcome(evidence, result, FAILURE_BUSY, attempt, elapsed)
