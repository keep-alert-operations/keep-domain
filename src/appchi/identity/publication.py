"""Atomic directory checkpoint publication and known-revocation enforcement.

Run with the trusted directory-worker database identity. Network traversal must
finish before opening this transaction. The caller owns the commit boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from psycopg.types.json import Jsonb

from .directory import DirectoryEvidence, PrincipalKey


@dataclass(frozen=True)
class PublicationResult:
    accepted: bool
    semantic_revision: int
    revoked_principals: tuple[str, ...]
    changed_access: tuple[tuple[str, str], ...]
    bootstrap_ready: bool


def allocate_generation(conn) -> int:
    return conn.execute("SELECT nextval('directory_generation_seq') AS generation").fetchone()[
        "generation"
    ]


def _audit(conn, kind, evidence, tenant=None):
    conn.execute(
        """INSERT INTO audit_events(id,tenant_id,actor_id,actor_label,kind,evidence)
                 VALUES(%s,%s,NULL,'directory-synchronizer',%s,%s)""",
        (uuid4(), tenant, kind, Jsonb(evidence)),
    )


def _local_roles(conn):
    rows = conn.execute("""SELECT g.tenant_id,p.id AS user_id, max(CASE g.role WHEN 'admin' THEN 3 WHEN 'edit' THEN 2 ELSE 1 END) AS role
        FROM tenant_grants g JOIN principals p ON p.eligible AND NOT p.deleted AND p.kind='user'
        AND (g.principal_id=p.id OR EXISTS(SELECT 1 FROM directory_memberships m WHERE m.team_id=g.principal_id AND m.user_id=p.id))
        GROUP BY g.tenant_id,p.id""").fetchall()
    return {(str(row["tenant_id"]), str(row["user_id"])): row["role"] for row in rows}


def _rebuild_memberships(conn):
    # Cycle-safe recursive UNION (not UNION ALL) preserves alternate paths and
    # excludes verified deleted/disabled intermediates. Sources never cross.
    conn.execute("DELETE FROM directory_memberships")
    conn.execute("""WITH RECURSIVE reachable(team_id,member_id) AS (
        SELECT r.root_id,e.child_id FROM directory_root_checkpoints r
        JOIN principals p ON p.id=r.root_id AND p.kind='team' AND p.eligible AND NOT p.deleted
        JOIN directory_edges e ON e.parent_id=r.root_id
        UNION
        SELECT r.team_id,e.child_id FROM reachable r
        JOIN principals p ON p.id=r.member_id AND p.kind='team' AND p.eligible AND NOT p.deleted
        JOIN directory_edges e ON e.parent_id=r.member_id)
        INSERT INTO directory_memberships(team_id,user_id)
        SELECT DISTINCT r.team_id,r.member_id FROM reachable r JOIN principals p ON p.id=r.member_id
        WHERE p.kind='user' AND p.eligible AND NOT p.deleted""")


def publish(
    conn,
    evidence: DirectoryEvidence,
    *,
    superadmin_group: PrincipalKey,
    bootstrap_qualified: bool = False,
) -> PublicationResult:
    """Publish full evidence or independently verified negative facts only.

    bootstrap_qualified is supplied by the controlled configuration/qualification
    command, never a browser request. It cannot compensate for empty/incomplete
    group evidence. Ordinary refresh cannot lift a restore-integrity gate.
    """
    if superadmin_group.source != evidence.source:
        raise ValueError("superadmin group and directory evidence source must match")
    conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR UPDATE")
    previous = conn.execute(
        "SELECT COALESCE(max(semantic_revision),0) AS revision FROM directory_verifications"
    ).fetchone()["revision"]
    if conn.execute(
        "SELECT 1 FROM directory_verifications WHERE generation=%s", (evidence.generation,)
    ).fetchone():
        return PublicationResult(False, previous, (), (), False)
    before_roles = _local_roles(conn)
    before_admins = {tenant for (tenant, _), role in before_roles.items() if role == 3}
    current = {
        PrincipalKey(row["directory_source"], row["object_id"]): row
        for row in conn.execute(
            "SELECT * FROM principals WHERE directory_source=%s", (evidence.source,)
        ).fetchall()
    }
    # An older completed cycle cannot overwrite a newer observation of ANY
    # covered dependency. Negatives are independently fenced below.
    accepted = evidence.complete and all(
        current.get(k, {}).get("evidence_generation", 0) < evidence.generation
        for k in evidence.objects
    )
    changed, revoked = False, []
    applicable = (
        evidence.objects if accepted else {k: evidence.objects[k] for k in evidence.negative_keys}
    )
    for key, obj in applicable.items():
        old = current.get(key)
        if old and old["evidence_generation"] >= evidence.generation:
            continue
        # A missing object's tombstone must retain its previously known type.
        kind = old["kind"] if old and obj.deleted else obj.kind
        values = (kind, obj.label, obj.eligible, obj.deleted)
        if old is None or values != (
            old["kind"],
            old["display_name"],
            old["eligible"],
            old["deleted"],
        ):
            changed = True
        row = conn.execute(
            """INSERT INTO principals(directory_source,object_id,kind,display_name,eligible,deleted,evidence_generation,verified_at)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(directory_source,object_id) DO UPDATE SET
            kind=EXCLUDED.kind,display_name=EXCLUDED.display_name,eligible=EXCLUDED.eligible,deleted=EXCLUDED.deleted,
            evidence_generation=EXCLUDED.evidence_generation,verified_at=EXCLUDED.verified_at RETURNING *""",
            (key.source, key.object_id, *values, evidence.generation, evidence.completed_at),
        ).fetchone()
        current[key] = row
        if not obj.eligible or obj.deleted:
            conn.execute(
                "UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()),tokens=NULL WHERE principal_id=%s",
                (row["id"],),
            )
            if old and old["eligible"] and not old["deleted"]:
                revoked.append(str(row["id"]))
    if accepted:
        for key, children in evidence.edges.items():
            parent = current[key]["id"]
            previous_edges = {
                row["child_id"]
                for row in conn.execute(
                    "SELECT child_id FROM directory_edges WHERE parent_id=%s", (parent,)
                ).fetchall()
            }
            child_ids = {current[child]["id"] for child in children}
            changed = changed or previous_edges != child_ids
            conn.execute("DELETE FROM directory_edges WHERE parent_id=%s", (parent,))
            for child in sorted(child_ids):
                conn.execute(
                    "INSERT INTO directory_edges(parent_id,child_id) VALUES(%s,%s)", (parent, child)
                )
        for key in evidence.roots:
            conn.execute(
                """INSERT INTO directory_root_checkpoints(root_id,generation,verified_at,semantic_digest)
                VALUES(%s,%s,%s,%s) ON CONFLICT(root_id) DO UPDATE SET generation=EXCLUDED.generation,
                verified_at=EXCLUDED.verified_at,semantic_digest=EXCLUDED.semantic_digest""",
                (
                    current[key]["id"],
                    evidence.generation,
                    evidence.completed_at,
                    evidence.semantic_digest,
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
                    "roots": sorted(k.object_id for k in evidence.roots),
                    "objects": sorted(k.object_id for k in evidence.objects),
                    "accepted": accepted,
                }
            ),
            Jsonb(list(evidence.failures)),
            evidence.target_missed,
        ),
    )
    if not accepted and not applicable:
        return PublicationResult(False, revision, (), (), False)
    # Content revision may stay unchanged while a newly tracked root or changed
    # configured admin mapping changes derived authority. Fence every derivation,
    # including away-and-back changes, independently of semantic cursor revision.
    conn.execute(
        "UPDATE authorization_guards SET directory_revision=directory_revision+1 WHERE scope='identity'"
    )
    before_memberships = (
        {
            (row["team_id"], row["user_id"])
            for row in conn.execute("SELECT team_id,user_id FROM directory_memberships").fetchall()
        }
        if not changed
        else None
    )
    _rebuild_memberships(conn)
    membership_changed = before_memberships is not None and before_memberships != {
        (row["team_id"], row["user_id"])
        for row in conn.execute("SELECT team_id,user_id FROM directory_memberships").fetchall()
    }
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
        conn.execute("UPDATE principals SET super_admin=false WHERE super_admin")
        if global_after:
            conn.execute(
                "UPDATE principals SET super_admin=true WHERE id=ANY(%s::uuid[])",
                (list(global_after),),
            )
        global_changes = global_before ^ global_after
    # Tracking an already-known root or switching the configured admin mapping
    # can change derived content without changing any object/edge. Finalize the
    # same transaction's checkpoint before emitting revision-bound audit events.
    if not changed and (membership_changed or global_changes):
        revision += 1
        conn.execute(
            "UPDATE directory_verifications SET semantic_revision=%s WHERE generation=%s",
            (revision, evidence.generation),
        )
    for principal in sorted(global_changes):
        _audit(
            conn,
            "global_privilege_changed",
            {
                "principal_id": principal,
                "before": principal in global_before,
                "after": principal in global_after,
                "generation": evidence.generation,
                "semantic_revision": revision,
            },
        )
    after_roles = _local_roles(conn)
    changed_access = tuple(
        sorted(
            key
            for key in before_roles.keys() | after_roles.keys()
            if before_roles.get(key) != after_roles.get(key)
        )
    )
    for tenant, principal in changed_access:
        _audit(
            conn,
            "directory_access_changed",
            {
                "principal_id": principal,
                "before": before_roles.get((tenant, principal)),
                "after": after_roles.get((tenant, principal)),
                "generation": evidence.generation,
                "semantic_revision": revision,
            },
            tenant,
        )
    after_admins = {tenant for (tenant, _), role in after_roles.items() if role == 3}
    for tenant in sorted(before_admins ^ after_admins):
        _audit(
            conn,
            "local_admin_restored" if tenant in after_admins else "local_admin_vacancy",
            {"generation": evidence.generation, "semantic_revision": revision},
            tenant,
        )
    if previous == 0 and accepted:
        _audit(
            conn,
            "directory_baseline_established",
            {"generation": evidence.generation, "source": evidence.source},
        )
    ready = bool(
        accepted and superadmin_group in evidence.roots and global_after and bootstrap_qualified
    )
    if ready:
        # Only initial bootstrap; restore and independently raised integrity
        # gates need their dedicated reconciliation proof and cannot be lifted.
        conn.execute("""UPDATE capability_gates SET ready=true,reason='directory_bootstrap_verified'
                     WHERE capability='human_auth' AND ready=false AND reason='directory_bootstrap_required'""")
    return PublicationResult(accepted, revision, tuple(revoked), changed_access, ready)
