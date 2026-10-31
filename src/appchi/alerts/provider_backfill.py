"""One-time provider backfill for alerts stored before REV-55.

Each batch is one tenant transaction in the writers' lock order: the tenant
coordinator, then alert rows in ID order. An alert takes the provider and rule
URL of its latest applied source event (`history_id`), and a non-semantic
projection change carries them to search and live views without activity,
correlation or maintenance input. Alerts that already have a provider are
skipped, so a rerun changes nothing.
"""

from appchi.alerts.lifecycle import delivery_provider
from appchi.alerts.repository import publish, store_alert
from appchi.shared.transactions import coordinator

BATCH = 100
CAUSE = "provider-backfill"


def backfill_batch(conn, tenant, after=None, limit=BATCH):
    """Fill up to `limit` live alerts after `after`; return (filled, unresolved, last ID).

    The caller owns the tenant transaction. Unresolved alerts lack their latest
    source event and keep a null provider; the last ID is None when none remain.
    """
    _, now = coordinator(conn, tenant)
    rows = conn.execute(
        "SELECT a.* FROM alerts a JOIN alert_identities i ON i.tenant_id=a.tenant_id AND i.id=a.id"
        " WHERE a.tenant_id=%s AND a.provider IS NULL AND i.retired_at IS NULL"
        " AND (%s::uuid IS NULL OR a.id>%s::uuid) ORDER BY a.id LIMIT %s FOR UPDATE OF a",
        (tenant, after, after, limit),
    ).fetchall()
    filled, unresolved = [], []
    for row in rows:
        event = conn.execute(
            "SELECT adapter_version,raw_json FROM alert_source_events WHERE alert_id=%s AND id=%s",
            (row["id"], row["history_id"]),
        ).fetchone()
        if event is None:
            unresolved.append(row["id"])
            continue
        current = dict(row)
        current["provider"], current["alert_rule_url"] = delivery_provider(event)
        current["projection_version"] += 1
        store_alert(conn, current)
        publish(conn, row, current, now, CAUSE, semantic=False)
        filled.append(row["id"])
    return filled, unresolved, rows[-1]["id"] if rows else None


def backfill_tenant(db, tenant, limit=BATCH):
    """Backfill every live alert of one tenant in short batches; return the counts."""
    after, filled, unresolved = None, 0, []
    while True:
        with db.transaction(tenant) as conn:
            done, missing, after = backfill_batch(conn, tenant, after, limit)
        filled += len(done)
        unresolved += [str(alert) for alert in missing]
        if after is None:
            return {"tenant_id": str(tenant), "filled": filled, "unresolved": unresolved}
