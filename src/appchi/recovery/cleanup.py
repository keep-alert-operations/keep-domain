"""Bounded incident-owned cleanup after independent final protection.

Command payloads have their own protected fence before erasure; their original
fingerprints remain. Minimal counterpart links survive with retained alerts.
"""

from dataclasses import asdict
from hashlib import sha256
from uuid import UUID, uuid5
from time import monotonic

from psycopg import sql
from psycopg.types.json import Jsonb

from appchi.ingestion.native import canonical
from appchi.recovery.evidence import Evidence, append_verified
from appchi.recovery.incidents import ready, locked_incident
from appchi.shared.errors import unavailable
from appchi.shared.transactions import coordinator, command_parent_expired

COMMAND_NAMESPACE = UUID("de74a629-9901-47b0-8f86-49243d74a532")


def _command_evidence(job, state):
    return Evidence(
        str(job[state + "_id"]),
        str(job["tenant_id"]),
        "command",
        str(job["command_id"]),
        0,
        state,
        job["evidence_digest"],
    )


def compact_command(db, store, tenant, scope, command):
    with db.transaction(tenant) as conn:
        ready(conn)
        row = conn.execute(
            "SELECT * FROM command_receipts WHERE scope=%s AND command_id=%s FOR UPDATE",
            (scope, command),
        ).fetchone()
        if not row or not command_parent_expired(conn, scope, command):
            return False
        job = conn.execute(
            "SELECT * FROM command_content_retirements WHERE scope=%s AND command_id=%s",
            (scope, command),
        ).fetchone()
        if row["result"] is None:
            if not job or job["state"] != "cleaned":
                raise unavailable("command_erasure_proof_missing")
            return True
        if not job:
            identity = uuid5(COMMAND_NAMESPACE, scope + ":" + str(command))
            result_digest = sha256(canonical(row["result"])).hexdigest()
            digest = sha256(
                canonical(
                    {
                        "scope": scope,
                        "command_id": str(command),
                        "fingerprint": bytes(row["fingerprint"]).hex(),
                        "status": row["status"],
                        "result_digest": result_digest,
                    }
                )
            ).hexdigest()
            job = conn.execute(
                "INSERT INTO command_content_retirements(id,scope,command_id,tenant_id,fingerprint,result_digest,evidence_digest,intent_id,final_id,state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared') RETURNING *",
                (
                    identity,
                    scope,
                    command,
                    tenant,
                    row["fingerprint"],
                    result_digest,
                    digest,
                    uuid5(identity, "intent"),
                    uuid5(identity, "final"),
                ),
            ).fetchone()
    if job["state"] == "prepared":
        intent = append_verified(store, _command_evidence(job, "intent"))
        final = append_verified(store, _command_evidence(job, "final"))
        with db.transaction(tenant) as conn:
            conn.execute(
                "UPDATE command_content_retirements SET state='final_protected',intent_ack=%s,final_ack=%s,updated_at=clock_timestamp() WHERE id=%s AND state='prepared'",
                (Jsonb(asdict(intent)), Jsonb(asdict(final)), job["id"]),
            )
    with db.transaction(tenant) as conn:
        ready(conn)
        row = conn.execute(
            "SELECT * FROM command_receipts WHERE scope=%s AND command_id=%s FOR UPDATE",
            (scope, command),
        ).fetchone()
        current = conn.execute(
            "SELECT * FROM command_content_retirements WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if current["state"] == "cleaned":
            return True
        if (
            current["state"] != "final_protected"
            or not current["final_ack"]
            or not command_parent_expired(conn, scope, command)
            or bytes(row["fingerprint"]) != bytes(job["fingerprint"])
            or sha256(canonical(row["result"])).hexdigest() != job["result_digest"]
        ):
            raise unavailable("command_erasure_precondition_changed")
        conn.execute(
            "UPDATE command_receipts SET result=NULL WHERE scope=%s AND command_id=%s",
            (scope, command),
        )
        conn.execute(
            "UPDATE command_content_retirements SET state='cleaned',updated_at=clock_timestamp() WHERE id=%s",
            (job["id"],),
        )
    return True


def cleanup_counterpart_links(conn, tenant, incident, limit):
    """Revisit minimal links even after incident content has been erased."""
    coordinator(conn, tenant)
    return conn.execute(
        """DELETE FROM incident_alert_links WHERE (tenant_id,incident_id,alert_id) IN (
        SELECT l.tenant_id,l.incident_id,l.alert_id FROM incident_alert_links l
        JOIN incident_identities i ON i.tenant_id=l.tenant_id AND i.id=l.incident_id
        JOIN alert_identities a ON a.tenant_id=l.tenant_id AND a.id=l.alert_id
        WHERE l.tenant_id=%s AND l.incident_id=%s AND i.retired_at IS NOT NULL
        AND a.retired_at IS NOT NULL AND EXISTS (
          SELECT 1 FROM retirement_jobs j WHERE j.tenant_id=l.tenant_id AND j.resource_kind='alert'
          AND j.resource_id=l.alert_id AND j.state IN ('final_protected','cleaned') AND j.final_ack IS NOT NULL)
        ORDER BY l.alert_id LIMIT %s)""",
        (tenant, incident, limit),
    ).rowcount


def cleanup_incident(db, store, tenant, incident, *, limit=100):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup limit must be 1..100")
    with db.transaction(tenant) as conn:
        ready(conn)
        job = conn.execute(
            "SELECT * FROM retirement_jobs WHERE tenant_id=%s AND resource_kind='incident' AND resource_id=%s AND state IN ('final_protected','cleaned')",
            (tenant, incident),
        ).fetchone()
        if not job or not job["final_ack"]:
            return False
        if job["state"] == "cleaned":
            return cleanup_counterpart_links(conn, tenant, incident, limit) < limit
        commands = conn.execute(
            "SELECT c.scope,c.command_id FROM command_receipts c JOIN command_resources r ON r.scope=c.scope AND r.command_id=c.command_id WHERE r.tenant_id=%s AND r.resource_id=%s AND c.result IS NOT NULL ORDER BY c.scope,c.command_id LIMIT %s",
            (tenant, incident, limit + 1),
        ).fetchall()
    started = monotonic()
    for command in commands[:limit]:
        compact_command(db, store, tenant, command["scope"], command["command_id"])
        if monotonic() - started >= 0.1:
            return False
    if len(commands) > limit:
        return False
    with db.transaction(tenant) as conn:
        ready(conn)
        coordinator(conn, tenant)
        current = conn.execute("SELECT * FROM retirement_jobs WHERE id=%s", (job["id"],)).fetchone()
        if current["state"] == "cleaned":
            return True
        row = locked_incident(conn, tenant, incident)
        identity = conn.execute(
            "SELECT * FROM incident_identities WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant, incident),
        ).fetchone()
        if (
            current["state"] != "final_protected"
            or not current["final_ack"]
            or not identity["retired_at"]
            or identity["final_revision"] != job["final_version"]
            or row["revision"] != job["final_version"]
        ):
            raise unavailable("incident_erasure_precondition_changed")
        blocked = conn.execute(
            """SELECT
          EXISTS(SELECT 1 FROM incident_retention_holds WHERE tenant_id=%s AND incident_id=%s AND released_at IS NULL) OR
          EXISTS(SELECT 1 FROM alert_active_ownership WHERE tenant_id=%s AND incident_id=%s) OR
          EXISTS(SELECT 1 FROM correlation_contexts WHERE tenant_id=%s AND active_incident_id=%s) OR
          EXISTS(SELECT 1 FROM command_resources r JOIN command_receipts c USING(scope,command_id) WHERE r.tenant_id=%s AND r.resource_id=%s AND c.result IS NOT NULL) AS blocked""",
            (tenant, incident) * 4,
        ).fetchone()["blocked"]
        if blocked:
            return False
        remaining = limit
        for table in (
            "incident_note_revisions",
            "incident_notes",
            "incident_activity",
            "incident_cycles",
            "incident_search_tokens",
            "correlation_decisions",
        ):
            # Include partition identity: ctid alone is not unique across partitions.
            removed = conn.execute(
                sql.SQL(
                    "DELETE FROM {} WHERE (tableoid,ctid) IN (SELECT tableoid,ctid FROM {} WHERE tenant_id=%s AND incident_id=%s LIMIT %s)"
                ).format(sql.Identifier(table), sql.Identifier(table)),
                (tenant, incident, remaining),
            ).rowcount
            remaining -= removed
            if remaining == 0:
                return False
        removed = cleanup_counterpart_links(conn, tenant, incident, remaining)
        remaining -= removed
        if remaining == 0:
            return False
        released = conn.execute(
            "UPDATE correlation_revision_holds SET released_at=clock_timestamp() WHERE ctid IN "
            "(SELECT ctid FROM correlation_revision_holds WHERE tenant_id=%s AND consumer_kind='incident' "
            "AND reference=%s AND released_at IS NULL LIMIT %s)",
            (tenant, str(incident), remaining),
        ).rowcount
        remaining -= released
        if remaining == 0:
            return False
        conn.execute("DELETE FROM incidents WHERE tenant_id=%s AND id=%s", (tenant, incident))
        conn.execute(
            "UPDATE retirement_jobs SET state='cleaned',updated_at=clock_timestamp() WHERE id=%s AND state='final_protected'",
            (job["id"],),
        )
    return True
