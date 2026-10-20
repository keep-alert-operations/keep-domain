import hashlib
import unicodedata
from uuid import uuid4
from psycopg.types.json import Jsonb
from appchi.alerts.repository import publish, store_alert
from appchi.alerts.state import retained, pending, maintenance_adjust
from appchi.correlation.runtime import lock_contexts, release_alert
from appchi.shared.errors import AppError
from appchi.serialization import wire


def get_incident(conn, tenant, incident_id, lock=False):
    row = conn.execute(
        "SELECT i.* FROM incidents i JOIN incident_identities x ON x.id=i.id AND x.tenant_id=i.tenant_id WHERE i.tenant_id=%s AND i.id=%s AND x.retired_at IS NULL"
        + (" FOR UPDATE OF i" if lock else ""),
        (tenant, incident_id),
    ).fetchone()
    if not row:
        raise AppError("not_found", "Incident unavailable.", 404)
    return row


def tokens(text):
    token = ""
    result = set()
    for c in text:
        if unicodedata.category(c)[0] in "LMN" or c == "_":
            token += c
        elif token:
            result.add(token.casefold())
            token = ""
    if token:
        result.add(token.casefold())
    return result


def update_tokens(conn, tenant, incident_id):
    incident = get_incident(conn, tenant, incident_id)
    notes = conn.execute(
        "SELECT text FROM incident_notes WHERE tenant_id=%s AND incident_id=%s AND NOT deleted",
        (tenant, incident_id),
    ).fetchall()
    values = tokens(
        incident["title"]
        + " "
        + incident["description"]
        + " "
        + " ".join(row["text"] for row in notes)
    )
    conn.execute(
        "DELETE FROM incident_search_tokens WHERE tenant_id=%s AND incident_id=%s",
        (tenant, incident_id),
    )
    for token in values:
        if len(token.encode()) <= 3072:
            conn.execute(
                "INSERT INTO incident_search_tokens(tenant_id,incident_id,id,token_digest,token_text) VALUES(%s,%s,%s,%s,%s)",
                (tenant, incident_id, uuid4(), hashlib.sha256(token.encode()).digest(), token),
            )


def activity(conn, row, now, actor, kind, evidence, qualifying=True):
    recorded_now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    conn.execute(
        "INSERT INTO incident_activity(tenant_id,incident_id,id,kind,recorded_at,actor_id,evidence) VALUES(%s,%s,%s,%s,%s,%s,%s)",
        (
            row["tenant_id"],
            row["id"],
            uuid4(),
            kind,
            recorded_now,
            actor,
            Jsonb(wire({**evidence, "effective_at": now})),
        ),
    )
    conn.execute(
        "UPDATE incidents SET revision=revision+1,updated_at=%s,last_activity=CASE WHEN status<>'resolved' AND %s THEN greatest(last_activity,%s) ELSE last_activity END WHERE tenant_id=%s AND id=%s",
        (recorded_now, qualifying, now, row["tenant_id"], row["id"]),
    )
    conn.execute(
        "UPDATE tenant_view_state SET view_generation=view_generation+1,resource_generation=resource_generation+1 WHERE tenant_id=%s",
        (row["tenant_id"],),
    )


def alert_link_change(conn, row, now, actor, kind, catalog=None):
    updated = {
        **row,
        "revision": row["revision"] + 1,
        "projection_version": row["projection_version"] + 1,
    }
    updated, changed, _, order = maintenance_adjust(conn, row, updated, now, kind, catalog)
    store_alert(conn, updated)
    publish(
        conn,
        row,
        updated,
        now,
        kind,
        actor=actor,
        semantic=changed,
        original_order=order,
        maintenance_input_recorded=True,
    )


def link_set(conn, tenant, incident, ids, now, actor, unlink=False, catalog=None):
    if incident["status"] == "resolved":
        raise AppError("incident_resolved", "Reopen before changing links.", 409)
    alerts = {key: retained(conn, tenant, key, True) for key in sorted(ids)}
    for key, row in alerts.items():
        pending(conn, tenant, row)
        claim = conn.execute(
            "SELECT incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
            (tenant, key),
        ).fetchone()
        if not unlink and claim and claim["incident_id"] != incident["id"]:
            raise AppError(
                "ownership_conflict", "An alert already has an active incident owner.", 409
            )
    changed = []
    for key, row in alerts.items():
        link = conn.execute(
            "SELECT * FROM incident_alert_links WHERE tenant_id=%s AND incident_id=%s AND alert_id=%s AND unlinked_at IS NULL",
            (tenant, incident["id"], key),
        ).fetchone()
        if unlink and link:
            conn.execute(
                "UPDATE incident_alert_links SET unlinked_at=%s WHERE tenant_id=%s AND incident_id=%s AND alert_id=%s",
                (now, tenant, incident["id"], key),
            )
            conn.execute(
                "DELETE FROM alert_active_ownership WHERE tenant_id=%s AND incident_id=%s AND alert_id=%s",
                (tenant, incident["id"], key),
            )
            boundary(conn, tenant, key, now)
        elif not unlink and not link:
            conn.execute(
                "INSERT INTO incident_alert_links(tenant_id,incident_id,alert_id,linked_at) VALUES(%s,%s,%s,%s) ON CONFLICT(tenant_id,incident_id,alert_id) DO UPDATE SET linked_at=EXCLUDED.linked_at,unlinked_at=NULL",
                (tenant, incident["id"], key, now),
            )
            conn.execute(
                "INSERT INTO alert_active_ownership(tenant_id,alert_id,incident_id) VALUES(%s,%s,%s)",
                (tenant, key, incident["id"]),
            )
        else:
            continue
        changed.append(key)
        alert_link_change(
            conn, row, now, actor, "incident-unlink" if unlink else "incident-link", catalog
        )
    return changed


def boundary(conn, tenant, alert_id, now):
    release_alert(conn, tenant, alert_id, now)


def lock_linked_incidents(conn, tenant, alert_id, *, contexts_locked=False):
    """Lock the alert's linked contexts, then its open linked incidents.

    Pass contexts_locked=True only when the caller already locked a superset,
    such as lock_catalog with this alert among its targets.
    """
    if not contexts_locked:
        lock_contexts(conn, tenant, targets=(alert_id,), live=False)
    return conn.execute(
        "SELECT i.* FROM incidents i JOIN incident_alert_links l ON l.tenant_id=i.tenant_id AND l.incident_id=i.id WHERE l.tenant_id=%s AND l.alert_id=%s AND l.unlinked_at IS NULL AND i.status<>'resolved' ORDER BY i.id FOR UPDATE OF i",
        (tenant, alert_id),
    ).fetchall()


def linked_transition(conn, incidents, before, after, effective_at):
    if before is None or before["status"] == after["status"]:
        return
    for incident in incidents:
        activity(
            conn,
            incident,
            effective_at,
            None,
            "linked-alert-status",
            {"alert_id": after["id"], "before": before["status"], "after": after["status"]},
        )
