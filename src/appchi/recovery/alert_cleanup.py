"""Bounded alert-owned erasure after final evidence and consumer/proof release."""

from time import monotonic

from psycopg import sql

from appchi.recovery.cleanup import compact_command
from appchi.recovery.incidents import ready
from appchi.shared.transactions import coordinator
from appchi.shared.errors import unavailable


def dependencies_released(conn, tenant, alert, final_version):
    row = conn.execute(
        """SELECT
      EXISTS(SELECT 1 FROM alert_retention_holds WHERE tenant_id=%s AND alert_id=%s AND released_at IS NULL) OR
      EXISTS(SELECT 1 FROM search_rebuild_jobs WHERE hold_active) OR
      EXISTS(SELECT 1 FROM ingest_items WHERE tenant_id=%s AND alert_id=%s AND disposition='pending') OR
      EXISTS(SELECT 1 FROM correlation_journal j WHERE tenant_id=%s AND alert_id=%s AND change_order>
        coalesce((SELECT change_order FROM correlation_consumer_state WHERE tenant_id=j.tenant_id),0)) OR
      EXISTS(SELECT 1 FROM maintenance_effect_outbox WHERE tenant_id=%s AND alert_id=%s AND processed_at IS NULL) OR
      EXISTS(SELECT 1 FROM projection_work p JOIN tenant_view_state v USING(tenant_id)
        WHERE p.tenant_id=%s AND p.alert_id=%s AND p.seq>v.searchable_seq) OR
      EXISTS(SELECT 1 FROM application_outbox o WHERE o.tenant_id=%s AND (
        (o.stream='changed' AND o.stream_order IN (SELECT seq FROM projection_work WHERE tenant_id=%s AND alert_id=%s)) OR
        (o.stream='received' AND o.stream_order IN (SELECT admission_order FROM ingest_items WHERE tenant_id=%s AND alert_id=%s)))
        AND (o.published_at IS NULL OR
          NOT EXISTS(SELECT 1 FROM pipeline_receipts r WHERE r.outbox_id=o.id AND r.consumer_name=CASE WHEN o.stream='received' THEN 'processor' ELSE 'projection' END) OR
          (o.stream='changed' AND NOT EXISTS(SELECT 1 FROM pipeline_receipts r WHERE r.outbox_id=o.id AND r.consumer_name='correlation-wakeup')))) AS blocked""",
        (tenant, alert) * 5 + (tenant, tenant, alert, tenant, alert),
    ).fetchone()
    if row["blocked"]:
        return False
    marker = conn.execute(
        "SELECT 1 FROM projection_work WHERE tenant_id=%s AND alert_id=%s AND version=%s AND (snapshot->>'live'='false' OR snapshot->>'deleted'='true')",
        (tenant, alert, final_version),
    ).fetchone()
    if not marker:
        raise unavailable("retirement_projection_missing")
    return True


def cleanup_alert(db, store, tenant, alert, *, limit=100):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup limit must be 1..100")
    with db.transaction(tenant) as conn:
        ready(conn)
        job = conn.execute(
            "SELECT * FROM retirement_jobs WHERE tenant_id=%s AND resource_kind='alert' AND resource_id=%s AND state IN ('final_protected','cleaned')",
            (tenant, alert),
        ).fetchone()
        if not job or not job["final_ack"]:
            return False
        if job["state"] == "cleaned":
            return True
        commands = conn.execute(
            "SELECT c.scope,c.command_id FROM command_receipts c JOIN command_resources r USING(scope,command_id) WHERE r.tenant_id=%s AND r.resource_kind='alert' AND r.resource_id=%s AND c.result IS NOT NULL ORDER BY c.scope,c.command_id LIMIT %s",
            (tenant, alert, limit + 1),
        ).fetchall()
    started = monotonic()
    for command in commands[:limit]:
        compact_command(db, store, tenant, command["scope"], command["command_id"])
        if monotonic() - started >= 0.1:
            return False
    if len(commands) > limit:
        return False
    with db.transaction(tenant) as conn:
        # Always acquire the rebuild/cleanup guard before coordinator locks.
        conn.execute("SELECT pg_advisory_xact_lock(713411725)")
        ready(conn)
        coordinator(conn, tenant)
        job = conn.execute(
            "SELECT * FROM retirement_jobs WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if job["state"] == "cleaned":
            return True
        identity = conn.execute(
            "SELECT * FROM alert_identities WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant, alert),
        ).fetchone()
        if (
            not identity["retired_at"]
            or identity["final_version"] != job["final_version"]
            or not job["final_ack"]
        ):
            raise unavailable("alert_erasure_precondition_changed")
        if not dependencies_released(conn, tenant, alert, job["final_version"]):
            return False
        started = monotonic()
        cleared = conn.execute(
            "UPDATE ingest_items SET key_field='',identity_material=''::bytea,payload=NULL,raw_json=NULL WHERE id IN (SELECT id FROM ingest_items WHERE tenant_id=%s AND alert_id=%s AND (key_field<>'' OR length(identity_material)>0 OR payload IS NOT NULL OR raw_json IS NOT NULL) ORDER BY admission_order LIMIT %s)",
            (tenant, alert, limit),
        ).rowcount
        remaining = limit - cleared
        if remaining == 0 or monotonic() - started >= 0.1:
            return False
        # Maintenance head FK precedes its immutable input body; corrections
        # remove descendants first. All other foreign keys target identity fences.
        for table, extra, ordering in (
            ("alert_note_revisions", "", ""),
            ("alert_notes", "", ""),
            ("alert_source_events", "", ""),
            ("alert_activity", "", ""),
            ("alert_occurrences", "", ""),
            ("maintenance_alert_input_heads", "", ""),
            ("maintenance_alert_checkpoints", "", ""),
            ("maintenance_alert_inputs", "", ""),
            ("maintenance_cause_history", "", ""),
            ("maintenance_union_history", "", ""),
            ("maintenance_qualifier_effects", "", ""),
            ("maintenance_effect_outbox", "", "ORDER BY change_order DESC"),
            ("alert_maintenance_causes", "", ""),
            ("correlation_evidence", "", ""),
            ("correlation_journal", "", ""),
            ("projection_work", "AND version < " + str(job["final_version"]), ""),
        ):
            removed = conn.execute(
                sql.SQL(
                    "DELETE FROM {} WHERE (tableoid,ctid) IN (SELECT tableoid,ctid FROM {} WHERE tenant_id=%s AND alert_id=%s {} {} LIMIT %s)"
                ).format(
                    sql.Identifier(table), sql.Identifier(table), sql.SQL(extra), sql.SQL(ordering)
                ),
                (tenant, alert, remaining),
            ).rowcount
            remaining -= removed
            if remaining == 0 or monotonic() - started >= 0.1:
                return False
        # Minimal provenance stays with a surviving incident. The incident sweep
        # revisits these links when that parent later expires.
        removed = conn.execute(
            "DELETE FROM incident_alert_links WHERE (tenant_id,incident_id,alert_id) IN (SELECT l.tenant_id,l.incident_id,l.alert_id FROM incident_alert_links l JOIN incident_identities i ON i.tenant_id=l.tenant_id AND i.id=l.incident_id WHERE l.tenant_id=%s AND l.alert_id=%s AND i.retired_at IS NOT NULL AND EXISTS(SELECT 1 FROM retirement_jobs j WHERE j.tenant_id=l.tenant_id AND j.resource_kind='incident' AND j.resource_id=l.incident_id AND j.state IN ('final_protected','cleaned') AND j.final_ack IS NOT NULL) LIMIT %s)",
            (tenant, alert, remaining),
        ).rowcount
        if removed == remaining:
            return False
        conn.execute("DELETE FROM alerts WHERE tenant_id=%s AND id=%s", (tenant, alert))
        conn.execute(
            "UPDATE retirement_jobs SET state='cleaned',updated_at=clock_timestamp() WHERE id=%s",
            (job["id"],),
        )
    return True
