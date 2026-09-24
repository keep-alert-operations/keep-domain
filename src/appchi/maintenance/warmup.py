"""Bounded proof warmup; readiness observations never enable capabilities.

The host retains the keyset cursor, reports blocked alerts, and repeats sweeps.
An activation checker must lock all relevant tenant coordinators and recheck
input heads and catalog generations atomically with the capability update.
"""

from dataclasses import dataclass
from time import monotonic
from uuid import UUID

from appchi.shared.errors import AppError
from appchi.shared.transactions import coordinator

from .processing import reconcile_alert
from .runtime import lock_catalog, prepare_qualified_catalog, publish_reconciliation
from .temporal import MaintenanceProofError


@dataclass(frozen=True)
class WarmupPage:
    scanned: int
    completed: int
    cursor: str | None
    blocked: tuple[tuple[str, str], ...]


def warmup_page(database, tenant, profile, *, cursor=None, limit=100):
    """Reconcile at most 100 retained alerts, each in its own atomic transaction."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Warmup page must contain 1..100 alerts")
    position = UUID(str(cursor)) if cursor else UUID(int=0)
    catalog = prepare_qualified_catalog(database, tenant, profile)
    with database.transaction(tenant) as conn:
        rows = conn.execute(
            """SELECT a.id FROM alerts a JOIN alert_identities i USING(tenant_id,id)
            WHERE a.tenant_id=%s AND a.id>%s AND i.retired_at IS NULL
            ORDER BY a.id LIMIT %s""",
            (tenant, position, limit + 1),
        ).fetchall()
    from appchi.alerts.routes import pending, retained
    from appchi.incidents.routes import lock_linked_incidents

    scanned = completed = 0
    blocked = []
    started = monotonic()
    for row in rows[:limit]:
        # Yield only between complete transactions; always permit one unit.
        if scanned and monotonic() - started >= 0.1:
            break
        try:
            with database.transaction(tenant) as conn:
                _, now = coordinator(conn, tenant)
                lock_catalog(conn, catalog)
                lock_linked_incidents(conn, tenant, row["id"])
                before = retained(conn, tenant, row["id"], True)
                pending(conn, tenant, before)
                after, effects = reconcile_alert(conn, before, now, catalog=catalog)
                publish_reconciliation(conn, before, after, effects, now)
            completed += 1
        except MaintenanceProofError as error:
            blocked.append((str(row["id"]), str(error)))
        except AppError as error:
            if error.status not in (404, 409, 503):
                raise
            blocked.append((str(row["id"]), error.code))
        position = row["id"]
        scanned += 1
    return WarmupPage(
        scanned, completed, str(position) if scanned < len(rows) else None, tuple(blocked)
    )


def warmup_status(database, tenant):
    """A single SQL snapshot of retained baseline/head/catalog proof, not a gate."""
    with database.transaction(tenant) as conn:
        return proof_counts(conn, tenant)


def proof_counts(conn, tenant):
    return conn.execute(
        """SELECT count(*) AS retained,
            count(*) FILTER(WHERE h.input_revision IS NULL OR NOT EXISTS(
                SELECT 1 FROM maintenance_alert_inputs p WHERE p.tenant_id=a.tenant_id AND p.alert_id=a.id AND p.new_logical_alert
            )) AS missing_baseline,
            count(*) FILTER(WHERE c.complete AND c.input_revision=h.input_revision
                AND c.catalog_generation=v.maintenance_generation) AS complete,
            count(*) FILTER(WHERE NOT coalesce(c.complete AND c.input_revision=h.input_revision
                AND c.catalog_generation=v.maintenance_generation,false)) AS pending
            FROM alerts a JOIN alert_identities i USING(tenant_id,id)
            JOIN tenant_view_state v ON v.tenant_id=a.tenant_id
            LEFT JOIN maintenance_alert_input_heads h ON h.tenant_id=a.tenant_id AND h.alert_id=a.id
            LEFT JOIN maintenance_alert_checkpoints c ON c.tenant_id=a.tenant_id AND c.alert_id=a.id
            WHERE a.tenant_id=%s AND i.retired_at IS NULL""",
        (tenant,),
    ).fetchone()
