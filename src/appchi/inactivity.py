"""Bounded inactivity sweeps with authoritative rechecks under tenant coordination."""

from datetime import timedelta
from appchi.shared.transactions import coordinator
from appchi.shared.errors import AppError
from appchi.correlation.runtime import resolve_context
from appchi.alerts.state import retained, pending, maintenance_adjust
from appchi.alerts.lifecycle import apply_command
from appchi.alerts.repository import store_alert, publish
from appchi.incidents.state import (
    activity,
    alert_link_change,
    boundary,
    get_incident,
    linked_transition,
    lock_linked_incidents,
    resolve_when_alerts_resolved,
)
from appchi.maintenance.runtime import prepare_for_tenant, lock_catalog


def expire_alert(db, tenant, alert_id, profile=None):
    catalog = prepare_for_tenant(db, tenant, profile)
    with db.transaction(tenant) as conn:
        _, now = coordinator(conn, tenant)
        lock_catalog(conn, catalog, targets=[alert_id])
        linked = lock_linked_incidents(conn, tenant, alert_id)
        row = retained(conn, tenant, alert_id, True)
        pending(conn, tenant, row)
        if row["status"] != "firing" or now < row["last_source_activity"] + timedelta(days=30):
            return False
        updated, _ = apply_command(row, "set_status", "resolved", None, now)
        updated, changed, _, order = maintenance_adjust(
            conn, row, updated, now, "source-inactivity", catalog
        )
        store_alert(conn, updated)
        linked_transition(conn, linked, row, updated, now)
        publish(
            conn,
            row,
            updated,
            now,
            "source-inactivity",
            semantic=changed,
            original_order=order,
            maintenance_input_recorded=True,
        )
        resolve_when_alerts_resolved(conn, tenant, linked, now, catalog)
        return True


def expire_incident(db, tenant, incident_id, profile=None):
    catalog = prepare_for_tenant(db, tenant, profile)
    with db.transaction(tenant) as conn:
        _, now = coordinator(conn, tenant)
        targets = [
            link["alert_id"]
            for link in conn.execute(
                "SELECT alert_id FROM incident_alert_links WHERE tenant_id=%s AND incident_id=%s AND unlinked_at IS NULL",
                (tenant, incident_id),
            )
        ]
        lock_catalog(conn, catalog, targets=targets, incidents=[incident_id])
        row = get_incident(conn, tenant, incident_id, True)
        deadline = row["last_activity"] + timedelta(days=30)
        if row["status"] == "resolved" or now < deadline:
            return False
        alerts = conn.execute(
            "SELECT a.* FROM alerts a JOIN alert_identities ai ON ai.id=a.id AND ai.tenant_id=a.tenant_id AND ai.retired_at IS NULL JOIN incident_alert_links l ON l.alert_id=a.id AND l.tenant_id=a.tenant_id WHERE l.tenant_id=%s AND l.incident_id=%s AND l.unlinked_at IS NULL ORDER BY a.id FOR UPDATE OF a",
            (tenant, incident_id),
        ).fetchall()
        for alert in alerts:
            pending(conn, tenant, alert)
        for index, alert in enumerate(alerts):
            adjusted, changed, effects, _ = maintenance_adjust(
                conn, alert, alert, now, "maintenance-materialization", catalog
            )
            if changed or (effects and effects.history_changed):
                store_alert(conn, adjusted)
                publish(
                    conn,
                    alert,
                    adjusted,
                    now,
                    "maintenance-materialization",
                    semantic=changed,
                    maintenance_input_recorded=True,
                )
                alerts[index] = adjusted
        resolve_context(conn, row, now)
        conn.execute(
            "UPDATE incident_cycles SET resolved_at=%s,cause='inactivity' WHERE incident_id=%s AND id=%s",
            (now, incident_id, row["cycle_id"]),
        )
        conn.execute(
            "UPDATE incidents SET status='resolved',resolved_at=%s,retention_at=%s WHERE tenant_id=%s AND id=%s",
            (now, now + timedelta(days=90), tenant, incident_id),
        )
        conn.execute(
            "DELETE FROM alert_active_ownership WHERE tenant_id=%s AND incident_id=%s",
            (tenant, incident_id),
        )
        for alert in alerts:
            boundary(conn, tenant, alert["id"], now)
            alert_link_change(conn, alert, now, None, "incident-inactivity", catalog)
        activity(
            conn,
            row,
            now,
            None,
            "inactivity",
            {"deadline": deadline, "before": row["status"], "after": "resolved"},
            qualifying=False,
        )
        return True


def sweep(db, profile=None):
    with db.transaction() as conn:
        alerts = conn.execute(
            "SELECT a.tenant_id,a.id FROM alerts a JOIN alert_identities i ON i.id=a.id AND i.tenant_id=a.tenant_id AND i.retired_at IS NULL WHERE status='firing' AND last_source_activity<=clock_timestamp()-interval '30 days' AND NOT EXISTS(SELECT 1 FROM ingest_items q WHERE q.tenant_id=a.tenant_id AND q.version=a.schema_version AND q.key_digest=sha256(convert_to(a.key_field,'UTF8')) AND q.disposition='pending') ORDER BY last_source_activity,a.id LIMIT 100"
        ).fetchall()
        incidents = conn.execute(
            "SELECT i.tenant_id,i.id FROM incidents i JOIN incident_identities x ON x.id=i.id AND x.tenant_id=i.tenant_id AND x.retired_at IS NULL WHERE status<>'resolved' AND last_activity<=clock_timestamp()-interval '30 days' AND NOT EXISTS(SELECT 1 FROM incident_alert_links l JOIN alerts a ON a.tenant_id=l.tenant_id AND a.id=l.alert_id JOIN ingest_items q ON q.tenant_id=a.tenant_id AND q.version=a.schema_version AND q.key_digest=sha256(convert_to(a.key_field,'UTF8')) AND q.disposition='pending' WHERE l.tenant_id=i.tenant_id AND l.incident_id=i.id AND l.unlinked_at IS NULL) ORDER BY last_activity,i.id LIMIT 100"
        ).fetchall()
    for function, rows in ((expire_alert, alerts), (expire_incident, incidents)):
        for row in rows:
            try:
                function(db, row["tenant_id"], row["id"], profile=profile)
            except AppError as error:
                if error.code not in ("not_found", "source_updates_pending"):
                    raise
