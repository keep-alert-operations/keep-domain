"""Resumable alert retirement; independent evidence calls never hold database locks."""

from dataclasses import asdict
from hashlib import sha256
from uuid import uuid4
from psycopg.types.json import Jsonb

from keep.alerts.state import pending, retained
from keep.ingestion.native import canonical
from keep.recovery.evidence import Evidence, append_verified
from keep.recovery.incidents import ready
from keep.shared.errors import unavailable
from keep.shared.transactions import coordinator


def evidence(job, state):
    digest = sha256(
        canonical(
            {
                "attempt_id": str(job["id"]),
                "tenant_id": str(job["tenant_id"]),
                "alert_id": str(job["resource_id"]),
                "revision": str(job["expected_revision"]),
                "final_version": str(job["final_version"]),
            }
        )
    ).hexdigest()
    return Evidence(
        str(job[state + "_evidence_id"]),
        str(job["tenant_id"]),
        "alert",
        str(job["resource_id"]),
        job["final_version"],
        state,
        digest,
    )


def protect_final(db, store, job):
    ack = append_verified(store, evidence(job, "final"))
    with db.transaction(job["tenant_id"]) as conn:
        conn.execute(
            "UPDATE retirement_jobs SET state='final_protected',final_ack=%s,updated_at=clock_timestamp() WHERE id=%s AND state='retired'",
            (Jsonb(asdict(ack)), job["id"]),
        )
    return True


def protect_cancellations(db, store, tenant, alert_id):
    with db.transaction(tenant) as conn:
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='recovery' FOR SHARE"
        ).fetchone()
        if not gate or not gate["ready"]:
            raise unavailable("recovery_not_ready")
        cancelled = conn.execute(
            "SELECT * FROM retirement_jobs WHERE tenant_id=%s AND resource_kind='alert' AND resource_id=%s AND state='cancelled' AND cancel_ack IS NULL ORDER BY created_at LIMIT 101",
            (tenant, alert_id),
        ).fetchall()
    for job in cancelled[:100]:
        ack = append_verified(store, evidence(job, "cancel"))
        with db.transaction(tenant) as conn:
            conn.execute(
                "UPDATE retirement_jobs SET cancel_ack=%s WHERE id=%s AND cancel_ack IS NULL",
                (Jsonb(asdict(ack)), job["id"]),
            )

    if len(cancelled) > 100:
        raise unavailable("recovery_cancellation_backlog")


def retire_alert(db, store, tenant, alert_id):
    protect_cancellations(db, store, tenant, alert_id)
    # A caller may retry after logical retirement even when all content reads are fenced.
    with db.transaction(tenant) as conn:
        _, now = coordinator(conn, tenant)
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='recovery' FOR SHARE"
        ).fetchone()
        if not gate or not gate["ready"]:
            raise unavailable("recovery_not_ready")
        job = conn.execute(
            "SELECT * FROM retirement_jobs WHERE tenant_id=%s AND resource_kind='alert' AND resource_id=%s AND state IN ('retired','final_protected','cleaned') ORDER BY created_at DESC LIMIT 1",
            (tenant, alert_id),
        ).fetchone()
        if not job:
            row = retained(conn, tenant, alert_id, True)
            pending(conn, tenant, row)
            if conn.execute(
                "SELECT 1 FROM kafka_source_results WHERE tenant_id=%s AND alert_id=%s AND NOT kafka_confirmed LIMIT 1",
                (tenant, alert_id),
            ).fetchone():
                return False
            if conn.execute(
                "SELECT 1 FROM alert_retention_holds WHERE tenant_id=%s AND alert_id=%s AND released_at IS NULL LIMIT 1",
                (tenant, alert_id),
            ).fetchone():
                return False
            if row["status"] != "resolved" or not row["retention_at"] or now < row["retention_at"]:
                return False
            job = conn.execute(
                "INSERT INTO retirement_jobs(id,tenant_id,resource_kind,resource_id,expected_revision,final_version,state) VALUES(%s,%s,'alert',%s,%s,%s,'intent') ON CONFLICT(resource_kind,resource_id) WHERE state<>'cancelled' DO UPDATE SET updated_at=clock_timestamp() RETURNING *",
                (uuid4(), tenant, alert_id, row["revision"], row["projection_version"] + 1),
            ).fetchone()
    if job["state"] in ("final_protected", "cleaned"):
        return True
    if job["state"] == "retired":
        return protect_final(db, store, job)
    if job["state"] == "cancelled":
        ack = append_verified(store, evidence(job, "cancel"))
        with db.transaction(tenant) as conn:
            conn.execute(
                "UPDATE retirement_jobs SET cancel_ack=%s WHERE id=%s",
                (Jsonb(asdict(ack)), job["id"]),
            )
        return False
    ack = append_verified(store, evidence(job, "intent"))
    with db.transaction(tenant) as conn:
        ready(conn)
        _, now = coordinator(conn, tenant)
        # Serialize duplicate workers, then recheck all eligibility after the external call.
        current = conn.execute(
            "SELECT * FROM retirement_jobs WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if current["state"] in ("retired", "final_protected", "cancelled"):
            job = current
        else:
            linked = conn.execute(
                "SELECT i.id FROM incidents i JOIN incident_alert_links l ON l.incident_id=i.id AND l.tenant_id=i.tenant_id WHERE i.tenant_id=%s AND l.alert_id=%s AND l.unlinked_at IS NULL ORDER BY i.id FOR UPDATE OF i",
                (tenant, alert_id),
            ).fetchall()
            row = retained(conn, tenant, alert_id, True)
            queued = conn.execute(
                "SELECT 1 FROM ingest_items WHERE tenant_id=%s AND version=%s AND key_digest=%s AND disposition='pending' LIMIT 1",
                (tenant, row["schema_version"], sha256(row["key_field"].encode()).digest()),
            ).fetchone()
            hold = conn.execute(
                "SELECT 1 FROM alert_retention_holds WHERE tenant_id=%s AND alert_id=%s AND released_at IS NULL LIMIT 1",
                (tenant, alert_id),
            ).fetchone()
            eligible = (
                not hold
                and not queued
                and not conn.execute(
                    "SELECT 1 FROM kafka_source_results WHERE tenant_id=%s AND alert_id=%s AND NOT kafka_confirmed LIMIT 1",
                    (tenant, alert_id),
                ).fetchone()
                and row["revision"] == job["expected_revision"]
                and row["projection_version"] < job["final_version"]
                and row["status"] == "resolved"
                and row["retention_at"] is not None
                and now >= row["retention_at"]
            )
            if not eligible:
                conn.execute(
                    "UPDATE retirement_jobs SET state='cancelled',intent_ack=%s,updated_at=%s WHERE id=%s",
                    (Jsonb(asdict(ack)), now, job["id"]),
                )
                job = {**job, "state": "cancelled"}
            else:
                conn.execute(
                    "UPDATE alert_identities SET retired_at=%s,final_version=%s WHERE tenant_id=%s AND id=%s",
                    (now, job["final_version"], tenant, alert_id),
                )
                conn.execute(
                    "DELETE FROM alert_key_claims WHERE tenant_id=%s AND alert_id=%s",
                    (tenant, alert_id),
                )
                conn.execute(
                    "DELETE FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
                    (tenant, alert_id),
                )
                state = conn.execute(
                    "UPDATE tenant_work_state SET projection_seq=projection_seq+1,change_order=change_order+1 WHERE tenant_id=%s RETURNING projection_seq,change_order",
                    (tenant,),
                ).fetchone()
                conn.execute(
                    "UPDATE alert_identities SET current_projection_seq=%s WHERE tenant_id=%s AND id=%s",
                    (state["projection_seq"], tenant, alert_id),
                )
                conn.execute(
                    "INSERT INTO alert_retired_keys(tenant_id,schema_version,key_digest,retired_at) VALUES(%s,%s,%s,%s) ON CONFLICT(tenant_id,schema_version,key_digest) DO UPDATE SET retired_at=greatest(alert_retired_keys.retired_at,EXCLUDED.retired_at)",
                    (
                        tenant,
                        row["schema_version"],
                        sha256(row["key_field"].encode()).digest(),
                        now,
                    ),
                )
                conn.execute(
                    "DELETE FROM correlation_evidence WHERE tenant_id=%s AND alert_id=%s",
                    (tenant, alert_id),
                )
                snapshot = {
                    "id": str(alert_id),
                    "tenant_id": str(tenant),
                    "live": False,
                    "projection_version": str(job["final_version"]),
                }
                conn.execute(
                    "INSERT INTO projection_work(tenant_id,seq,alert_id,version,snapshot) VALUES(%s,%s,%s,%s,%s)",
                    (
                        tenant,
                        state["projection_seq"],
                        alert_id,
                        job["final_version"],
                        Jsonb(snapshot),
                    ),
                )
                conn.execute(
                    "INSERT INTO correlation_journal(tenant_id,change_order,alert_id,before_snapshot,after_snapshot,effective_at,cause) VALUES(%s,%s,%s,NULL,%s,%s,'retired')",
                    (tenant, state["change_order"], alert_id, Jsonb(snapshot), now),
                )
                conn.execute(
                    "UPDATE tenant_view_state SET purge_generation=purge_generation+1,view_generation=view_generation+1,resource_generation=resource_generation+%s WHERE tenant_id=%s",
                    (int(bool(linked)), tenant),
                )
                from keep.events import changed

                envelope = changed(
                    tenant=tenant,
                    alert=alert_id,
                    seq=state["projection_seq"],
                    version=job["final_version"],
                    snapshot=snapshot,
                    change_order=state["change_order"],
                    cause="retired",
                    effective_at=now,
                    recorded_at=now,
                )
                from keep.alert_notifications import remember

                remember(envelope)
                conn.execute(
                    "UPDATE retirement_jobs SET state='retired',intent_ack=%s,updated_at=%s WHERE id=%s",
                    (Jsonb(asdict(ack)), now, job["id"]),
                )
                conn.execute(
                    "UPDATE ingest_retry_keys SET expires_at=%s+interval '90 days' WHERE item_id IN(SELECT id FROM ingest_items WHERE tenant_id=%s AND alert_id=%s)",
                    (now, tenant, alert_id),
                )
                job = {**job, "state": "retired"}
    if job["state"] == "cancelled":
        ack = append_verified(store, evidence(job, "cancel"))
        with db.transaction(tenant) as conn:
            conn.execute(
                "UPDATE retirement_jobs SET cancel_ack=%s WHERE id=%s",
                (Jsonb(asdict(ack)), job["id"]),
            )
        return False
    return protect_final(db, store, job)
