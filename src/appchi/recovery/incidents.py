"""Incident retirement with independent intent/final/cancel protection.

Logical retirement keeps content inaccessible while final protection retries.
It never releases active ownership or changes a linked alert's lifecycle.
"""

from dataclasses import asdict
from hashlib import sha256
from uuid import uuid4

from psycopg.types.json import Jsonb

from appchi.correlation.runtime import lock_contexts
from appchi.ingestion.native import canonical
from appchi.recovery.evidence import Evidence, append_verified
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import coordinator


def evidence(job, state):
    digest = sha256(
        canonical(
            {
                "attempt_id": str(job["id"]),
                "tenant_id": str(job["tenant_id"]),
                "incident_id": str(job["resource_id"]),
                "revision": str(job["expected_revision"]),
                "final_revision": str(job["final_version"]),
            }
        )
    ).hexdigest()
    return Evidence(
        str(job[state + "_evidence_id"]),
        str(job["tenant_id"]),
        "incident",
        str(job["resource_id"]),
        job["final_version"],
        state,
        digest,
    )


def ready(conn):
    row = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='recovery' FOR SHARE"
    ).fetchone()
    if not row or not row["ready"]:
        raise unavailable("recovery_not_ready")


def locked_incident(conn, tenant, incident):
    lock_contexts(conn, tenant)
    row = conn.execute(
        "SELECT * FROM incidents WHERE tenant_id=%s AND id=%s FOR UPDATE", (tenant, incident)
    ).fetchone()
    if not row:
        raise AppError("not_found", "Incident unavailable.", 404)
    conn.execute(
        "SELECT a.id FROM alerts a JOIN incident_alert_links l ON l.tenant_id=a.tenant_id AND l.alert_id=a.id WHERE l.tenant_id=%s AND l.incident_id=%s ORDER BY a.id FOR UPDATE OF a",
        (tenant, incident),
    ).fetchall()
    return row


def eligible(conn, row, now):
    tenant, incident = row["tenant_id"], row["id"]
    if row["status"] != "resolved" or row["retention_at"] is None or now < row["retention_at"]:
        return False
    blocked = conn.execute(
        """SELECT
        EXISTS(SELECT 1 FROM alert_active_ownership WHERE tenant_id=%s AND incident_id=%s) OR
        EXISTS(SELECT 1 FROM correlation_contexts WHERE tenant_id=%s AND active_incident_id=%s) OR
        EXISTS(SELECT 1 FROM incident_retention_holds WHERE tenant_id=%s AND incident_id=%s AND released_at IS NULL) OR
        EXISTS(SELECT 1 FROM incident_alert_links l JOIN alert_key_claims k ON k.tenant_id=l.tenant_id AND k.alert_id=l.alert_id
          JOIN ingest_items i ON i.tenant_id=k.tenant_id AND i.version=k.schema_version AND i.key_digest=k.key_digest
          WHERE l.tenant_id=%s AND l.incident_id=%s AND i.disposition='pending') AS blocked""",
        (tenant, incident) * 4,
    ).fetchone()["blocked"]
    return not blocked


def protect(db, store, job, state):
    ack = append_verified(store, evidence(job, state))
    with db.transaction(job["tenant_id"]) as conn:
        if state == "cancel":
            conn.execute(
                "UPDATE retirement_jobs SET cancel_ack=%s,updated_at=clock_timestamp() WHERE id=%s AND state='cancelled'",
                (Jsonb(asdict(ack)), job["id"]),
            )
        else:
            conn.execute(
                "UPDATE retirement_jobs SET final_ack=%s,state='final_protected',updated_at=clock_timestamp() WHERE id=%s AND state='retired'",
                (Jsonb(asdict(ack)), job["id"]),
            )


def retire_incident(db, store, tenant, incident):
    with db.transaction(tenant) as conn:
        ready(conn)
        cancelled = conn.execute(
            "SELECT * FROM retirement_jobs WHERE tenant_id=%s AND resource_kind='incident' AND resource_id=%s AND state='cancelled' AND cancel_ack IS NULL ORDER BY created_at LIMIT 101",
            (tenant, incident),
        ).fetchall()
    for job in cancelled[:100]:
        protect(db, store, job, "cancel")
    if len(cancelled) > 100:
        raise unavailable("recovery_cancellation_backlog")
    with db.transaction(tenant) as conn:
        ready(conn)
        _, now = coordinator(conn, tenant)
        job = conn.execute(
            "SELECT * FROM retirement_jobs WHERE tenant_id=%s AND resource_kind='incident' AND resource_id=%s AND state<>'cancelled'",
            (tenant, incident),
        ).fetchone()
        if not job:
            row = locked_incident(conn, tenant, incident)
            if not eligible(conn, row, now):
                return False
            identity = conn.execute(
                "SELECT retired_at FROM incident_identities WHERE tenant_id=%s AND id=%s",
                (tenant, incident),
            ).fetchone()
            if identity["retired_at"] is not None:
                raise unavailable("incident_retirement_proof_missing")
            job = conn.execute(
                "INSERT INTO retirement_jobs(id,tenant_id,resource_kind,resource_id,expected_revision,final_version,state) VALUES(%s,%s,'incident',%s,%s,%s,'intent') RETURNING *",
                (uuid4(), tenant, incident, row["revision"], row["revision"] + 1),
            ).fetchone()
    if job["state"] in ("final_protected", "cleaned"):
        return True
    if job["state"] == "retired":
        protect(db, store, job, "final")
        return True
    ack = append_verified(store, evidence(job, "intent"))
    with db.transaction(tenant) as conn:
        ready(conn)
        _, now = coordinator(conn, tenant)
        row = locked_incident(conn, tenant, incident)
        job = conn.execute(
            "SELECT * FROM retirement_jobs WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if job["state"] == "intent":
            if row["revision"] != job["expected_revision"] or not eligible(conn, row, now):
                conn.execute(
                    "UPDATE retirement_jobs SET state='cancelled',intent_ack=%s,updated_at=%s WHERE id=%s",
                    (Jsonb(asdict(ack)), now, job["id"]),
                )
                job = {**job, "state": "cancelled"}
            else:
                conn.execute(
                    "UPDATE incident_identities SET retired_at=%s,final_revision=%s WHERE tenant_id=%s AND id=%s AND retired_at IS NULL",
                    (now, job["final_version"], tenant, incident),
                )
                conn.execute(
                    "UPDATE incidents SET revision=%s,updated_at=%s WHERE tenant_id=%s AND id=%s",
                    (job["final_version"], now, tenant, incident),
                )
                conn.execute(
                    "UPDATE tenant_view_state SET view_generation=view_generation+1,resource_generation=resource_generation+1,purge_generation=purge_generation+1 WHERE tenant_id=%s",
                    (tenant,),
                )
                conn.execute(
                    "UPDATE retirement_jobs SET state='retired',intent_ack=%s,updated_at=%s WHERE id=%s",
                    (Jsonb(asdict(ack)), now, job["id"]),
                )
                job = {**job, "state": "retired"}
    if job["state"] == "cancelled":
        if job["cancel_ack"] is None:
            protect(db, store, job, "cancel")
        return False
    if job["state"] == "retired":
        protect(db, store, job, "final")
    return True
