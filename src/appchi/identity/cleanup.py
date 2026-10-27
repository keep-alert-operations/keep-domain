"""Bounded trusted-access assignment reconciliation and protected audit expiry."""

from dataclasses import asdict, dataclass
from datetime import UTC, timedelta
import hashlib
from uuid import uuid4

from psycopg.types.json import Jsonb

from appchi.ingestion.native import canonical
from appchi.recovery.evidence import Evidence, append_verified
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import coordinator
from appchi.serialization import wire


def assignment_proof(conn, tenant_id, principal_id):
    """One coherent accepted-state query; verification age is never a denial."""
    row = conn.execute(
        """SELECT p.id,p.display_name,p.eligible,p.deleted,p.evidence_generation,p.verified_at,t.revision AS tenant_revision,
        (p.kind='user' AND p.eligible AND NOT p.deleted AND (p.super_admin OR t.kind='global' OR EXISTS(
          SELECT 1 FROM tenant_grants g WHERE g.tenant_id=t.id AND g.role IN ('edit','admin') AND
          (g.principal_id=p.id OR EXISTS(SELECT 1 FROM directory_memberships m WHERE m.team_id=g.principal_id AND m.user_id=p.id))))) AS qualifies
        FROM principals p CROSS JOIN tenants t WHERE p.id=%s AND t.id=%s""",
        (principal_id, tenant_id),
    ).fetchone()
    if row is None:
        raise unavailable("assignment_identity_proof_missing")
    return row


def visible_assignee(conn, tenant_id, principal_id):
    """Read-only immediate presentation while durable cleanup catches up."""
    if principal_id is None:
        return None, False
    proof = assignment_proof(conn, tenant_id, principal_id)
    return (principal_id, False) if proof["qualifies"] else (None, True)


def cleanup_assignment(database, tenant_id, kind, resource_id, expected_assignee, *, profile=None):
    if kind not in ("alert", "incident"):
        raise ValueError("Unsupported assignment resource")
    from appchi.maintenance.runtime import prepare_for_tenant, lock_catalog

    catalog = prepare_for_tenant(database, tenant_id, profile) if kind == "alert" else None
    with database.transaction(tenant_id) as conn:
        # Serialize against accepted directory publication AND grant changes.
        conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE")
        _, now = coordinator(conn, tenant_id)
        if kind == "alert":
            from appchi.alerts.state import retained, pending, maintenance_adjust
            from appchi.alerts.repository import publish, store_alert
            from appchi.incidents.state import lock_linked_incidents

            lock_catalog(conn, catalog, targets=[resource_id])
            lock_linked_incidents(conn, tenant_id, resource_id)
            row = retained(conn, tenant_id, resource_id, True)
        else:
            from appchi.incidents.state import get_incident, activity

            hint = conn.execute(
                "SELECT context_id FROM incidents WHERE tenant_id=%s AND id=%s",
                (tenant_id, resource_id),
            ).fetchone()
            if hint and hint["context_id"]:
                conn.execute(
                    "SELECT id FROM correlation_contexts WHERE tenant_id=%s AND id=%s FOR UPDATE",
                    (tenant_id, hint["context_id"]),
                )
            row = get_incident(conn, tenant_id, resource_id, True)
        if row["assignee_id"] is None or str(row["assignee_id"]) != str(expected_assignee):
            return False
        proof = assignment_proof(conn, tenant_id, row["assignee_id"])
        if proof["qualifies"]:
            return False
        evidence = {
            "cause": "eligibility_lost",
            "actor_type": "system",
            "actor_label": "identity-reconciler",
            "before_assignee_id": row["assignee_id"],
            "before_assignee_label": proof["display_name"],
            "after_assignee_id": None,
            "directory_generation": proof["evidence_generation"],
            "verified_at": proof["verified_at"],
            "tenant_revision": proof["tenant_revision"],
        }
        if kind == "alert":
            pending(conn, tenant_id, row)
            updated = dict(
                row,
                assignee_id=None,
                revision=row["revision"] + 1,
                projection_version=row["projection_version"] + 1,
            )
            updated, changed, _, order = maintenance_adjust(
                conn, row, updated, now, "eligibility_lost", catalog
            )
            store_alert(conn, updated)
            publish(
                conn,
                row,
                updated,
                now,
                "eligibility_lost",
                semantic=changed,
                original_order=order,
                maintenance_input_recorded=True,
                activity_evidence=evidence,
            )
        else:
            conn.execute(
                "UPDATE incidents SET assignee_id=NULL WHERE tenant_id=%s AND id=%s",
                (tenant_id, resource_id),
            )
            activity(conn, row, now, None, "eligibility_lost", evidence, qualifying=False)
        return True


@dataclass(frozen=True)
class CleanupPage:
    scanned: int
    cleared: int
    cursor: tuple[str, str, str] | None
    pending: tuple[tuple[str, str, str], ...]


def cleanup_assignments(database, *, profile=None, limit=100, cursor=None, tenant_id=None):
    """Bounded keyset scan; host retains cursor and cycles again after end."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup page must contain 1..100 candidates")
    with database.transaction() as conn:
        rows = conn.execute(
            """SELECT * FROM (
            SELECT a.tenant_id,'alert' AS kind,a.id,a.assignee_id FROM alerts a JOIN alert_identities i ON i.tenant_id=a.tenant_id AND i.id=a.id WHERE a.assignee_id IS NOT NULL AND i.retired_at IS NULL
            UNION ALL SELECT a.tenant_id,'incident' AS kind,a.id,a.assignee_id FROM incidents a JOIN incident_identities i ON i.tenant_id=a.tenant_id AND i.id=a.id WHERE a.assignee_id IS NOT NULL AND i.retired_at IS NULL
            ) candidates WHERE (%s::uuid IS NULL OR tenant_id=%s) AND (%s::uuid IS NULL OR (tenant_id,kind,id)>(%s::uuid,%s,%s::uuid)) ORDER BY tenant_id,kind,id LIMIT %s""",
            (
                tenant_id,
                tenant_id,
                cursor[0] if cursor else None,
                *(cursor or (None, None, None)),
                limit + 1,
            ),
        ).fetchall()
    cleared, pending_rows = 0, []
    for row in rows[:limit]:
        try:
            cleared += int(
                cleanup_assignment(
                    database,
                    row["tenant_id"],
                    row["kind"],
                    row["id"],
                    row["assignee_id"],
                    profile=profile,
                )
            )
        except AppError as error:
            if error.code == "not_found":
                continue
            if error.code not in (
                "source_updates_pending",
                "maintenance_catalog_changed",
                "maintenance_proof_unavailable",
            ):
                raise
            pending_rows.append((str(row["tenant_id"]), row["kind"], str(row["id"])))
    last = rows[limit - 1] if len(rows) > limit else None
    return CleanupPage(
        min(len(rows), limit),
        cleared,
        (str(last["tenant_id"]), last["kind"], str(last["id"])) if last else None,
        tuple(pending_rows),
    )


def hold_audit(conn, event_id, kind, reference):
    """Trusted command/recovery owners hold evidence before exposing dependency."""
    if (
        kind not in ("unfinished_command", "reference", "recovery")
        or not 1 <= len(reference) <= 256
    ):
        raise ValueError("Invalid audit dependency")
    if not conn.execute(
        "SELECT id FROM audit_events WHERE id=%s FOR UPDATE", (event_id,)
    ).fetchone():
        raise AppError("not_found", "Audit evidence is unavailable.", 404)
    if conn.execute("SELECT 1 FROM audit_expiry_fences WHERE event_id=%s", (event_id,)).fetchone():
        raise AppError("not_found", "Audit evidence is unavailable.", 404)
    conn.execute(
        "INSERT INTO audit_retention_holds(event_id,kind,reference) VALUES(%s,%s,%s) ON CONFLICT(event_id,kind,reference) DO UPDATE SET released_at=NULL",
        (event_id, kind, reference),
    )


def release_audit_hold(conn, event_id, kind, reference):
    conn.execute(
        "UPDATE audit_retention_holds SET released_at=COALESCE(released_at,clock_timestamp()) WHERE event_id=%s AND kind=%s AND reference=%s",
        (event_id, kind, reference),
    )


def _retention_ready(conn):
    rows = conn.execute(
        "SELECT capability,ready FROM capability_gates WHERE capability IN ('recovery','audit_retention')"
    ).fetchall()
    if {row["capability"] for row in rows if row["ready"]} != {"recovery", "audit_retention"}:
        raise unavailable("audit_retention_unready")


def _audit_digest(row):
    row = dict(row, recorded_at=row["recorded_at"].astimezone(UTC))
    return hashlib.sha256(canonical(wire(row))).hexdigest()


def _evidence(job, state):
    return Evidence(
        str(job[state + "_id"]),
        str(job["scope_tenant_id"]),
        "audit",
        str(job["event_id"]),
        1,
        state,
        job["digest"],
    )


def _protect(store, job, state):
    evidence = _evidence(job, state)
    ack = append_verified(store, evidence)
    return Jsonb(asdict(ack))


def retire_audit(database, store, event_id):
    """Protect minimal intent, recheck holds/expiry, delete, protect final.

    Network operations occur outside SQL transactions. A final-write failure
    leaves a durable minimal fence and resumable retired job, never false success.
    Platform events use immutable Global as the external evidence scope only.
    """
    if store is None:
        raise unavailable("audit_retention_protection_required")
    with database.transaction() as conn:
        _retention_ready(conn)
        cancellations = conn.execute(
            "SELECT * FROM audit_retirement_jobs WHERE event_id=%s AND state='cancelled' AND cancel_ack IS NULL ORDER BY created_at LIMIT 101",
            (event_id,),
        ).fetchall()
    if len(cancellations) > 100:
        raise unavailable("audit_retention_cancellation_backlog")
    for job in cancellations:
        ack = _protect(store, job, "cancel")
        with database.transaction() as conn:
            conn.execute(
                "UPDATE audit_retirement_jobs SET cancel_ack=%s,updated_at=clock_timestamp() WHERE id=%s",
                (ack, job["id"]),
            )
    with database.transaction() as conn:
        _retention_ready(conn)
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
            ("audit-expiry:" + str(event_id),),
        )
        job = conn.execute(
            "SELECT * FROM audit_retirement_jobs WHERE event_id=%s AND state<>'cancelled' FOR UPDATE",
            (event_id,),
        ).fetchone()
        if not job:
            event = conn.execute(
                "SELECT * FROM audit_events WHERE id=%s FOR UPDATE", (event_id,)
            ).fetchone()
            if not event:
                return False
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            if now.astimezone(UTC) < event["recorded_at"].astimezone(UTC) + timedelta(days=365):
                return False
            if conn.execute(
                "SELECT 1 FROM audit_retention_holds WHERE event_id=%s AND released_at IS NULL",
                (event_id,),
            ).fetchone():
                return False
            scope = (
                event["tenant_id"]
                or conn.execute("SELECT id FROM tenants WHERE kind='global'").fetchone()["id"]
            )
            job = conn.execute(
                """INSERT INTO audit_retirement_jobs(id,event_id,scope_tenant_id,event_tenant_id,event_recorded_at,digest,state,intent_id,final_id,cancel_id,created_at,updated_at)
                VALUES(%s,%s,%s,%s,%s,%s,'prepared',%s,%s,%s,%s,%s) RETURNING *""",
                (
                    uuid4(),
                    event_id,
                    scope,
                    event["tenant_id"],
                    event["recorded_at"],
                    _audit_digest(event),
                    uuid4(),
                    uuid4(),
                    uuid4(),
                    now,
                    now,
                ),
            ).fetchone()
    if job["state"] == "prepared":
        ack = _protect(store, job, "intent")
        with database.transaction() as conn:
            _retention_ready(conn)
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                ("audit-expiry:" + str(event_id),),
            )
            event = conn.execute(
                "SELECT * FROM audit_events WHERE id=%s FOR UPDATE", (event_id,)
            ).fetchone()
            current = conn.execute(
                "SELECT * FROM audit_retirement_jobs WHERE id=%s FOR UPDATE", (job["id"],)
            ).fetchone()
            if current["state"] == "prepared":
                now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
                held = conn.execute(
                    "SELECT 1 FROM audit_retention_holds WHERE event_id=%s AND released_at IS NULL",
                    (event_id,),
                ).fetchone()
                valid = (
                    event
                    and not held
                    and now.astimezone(UTC)
                    >= event["recorded_at"].astimezone(UTC) + timedelta(days=365)
                    and _audit_digest(event) == job["digest"]
                )
                state = "retired" if valid else "cancelled"
                conn.execute(
                    "UPDATE audit_retirement_jobs SET state=%s,intent_ack=%s,updated_at=%s WHERE id=%s",
                    (state, ack, now, job["id"]),
                )
                if valid:
                    conn.execute(
                        "INSERT INTO audit_expiry_fences(event_id,scope_tenant_id,event_recorded_at,final_evidence_id,digest,retired_at) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                        (
                            event_id,
                            job["scope_tenant_id"],
                            job["event_recorded_at"],
                            job["final_id"],
                            job["digest"],
                            now,
                        ),
                    )
                job = dict(current, state=state)
            else:
                job = current
    if job["state"] == "cancelled":
        ack = _protect(store, job, "cancel")
        with database.transaction() as conn:
            conn.execute(
                "UPDATE audit_retirement_jobs SET cancel_ack=%s,updated_at=clock_timestamp() WHERE id=%s",
                (ack, job["id"]),
            )
        return False
    if job["state"] == "final_protected":
        return _delete_finalized_audit(database, job)
    ack = _protect(store, job, "final")
    with database.transaction() as conn:
        conn.execute(
            "UPDATE audit_retirement_jobs SET state='final_protected',final_ack=%s,updated_at=clock_timestamp() WHERE id=%s AND state='retired'",
            (ack, job["id"]),
        )
    return _delete_finalized_audit(database, job)


def _delete_finalized_audit(database, job):
    """Physical payload deletion follows independently protected final evidence."""
    with database.transaction() as conn:
        _retention_ready(conn)
        current = conn.execute(
            "SELECT * FROM audit_retirement_jobs WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if current["state"] != "final_protected" or not current["final_ack"]:
            raise unavailable("audit_final_protection_required")
        event = conn.execute(
            "SELECT * FROM audit_events WHERE id=%s FOR UPDATE", (job["event_id"],)
        ).fetchone()
        if not event:
            return True
        if _audit_digest(event) != job["digest"]:
            raise unavailable("audit_retention_body_changed")
        if conn.execute(
            "SELECT 1 FROM audit_retention_holds WHERE event_id=%s AND released_at IS NULL",
            (job["event_id"],),
        ).fetchone():
            raise unavailable("audit_retention_dependency_changed")
        conn.execute(
            "DELETE FROM audit_retention_holds WHERE event_id=%s AND released_at IS NOT NULL",
            (job["event_id"],),
        )
        conn.execute("DELETE FROM audit_events WHERE id=%s", (job["event_id"],))
        return True


def purge_audit_batch(database, store, *, limit=100):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Audit batch must contain 1..100 events")
    with database.transaction() as conn:
        _retention_ready(conn)
        rows = conn.execute(
            """SELECT event_id FROM (
            SELECT j.event_id,j.created_at AS priority FROM audit_retirement_jobs j WHERE state IN ('prepared','retired')
              OR (state='final_protected' AND EXISTS(SELECT 1 FROM audit_events a WHERE a.id=j.event_id))
            UNION SELECT a.id AS event_id,a.recorded_at AS priority FROM audit_events a
              WHERE a.recorded_at<=clock_timestamp()-interval '8760 hours'
              AND NOT EXISTS(SELECT 1 FROM audit_retention_holds h WHERE h.event_id=a.id AND h.released_at IS NULL)
            ) work GROUP BY event_id ORDER BY min(priority),event_id LIMIT %s""",
            (limit,),
        ).fetchall()
    return sum(int(retire_audit(database, store, row["event_id"])) for row in rows)
