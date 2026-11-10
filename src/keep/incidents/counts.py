"""Exact retained-link counts with authoritative suppression at one DB clock."""

from keep.shared.errors import unavailable

EMPTY = {
    "total_linked": 0,
    "unavailable": 0,
    "suppressed": 0,
    "missing_proof": False,
    "maintenance_updating": False,
}


def _grouped(conn, tenant, incidents):
    """One grouped read for every listed incident; incidents without links are absent."""
    state = conn.execute(
        """SELECT maintenance_generation,clock_timestamp() AS now
        FROM tenant_view_state WHERE tenant_id=%s""",
        (tenant,),
    ).fetchone()
    rows = conn.execute(
        """WITH clock AS (SELECT %s::timestamptz AS at), current_links AS (
        SELECT l.incident_id,a.id,a.suppressed AS stored_suppressed,cp.complete,cp.catalog_generation,
            cp.current_suppressed,
            (coalesce(a.source_suppressed,false) OR EXISTS(
                SELECT 1 FROM alert_maintenance_causes c JOIN maintenance_segments s
                ON s.tenant_id=c.tenant_id AND s.id=c.segment_id CROSS JOIN clock
                WHERE c.tenant_id=a.tenant_id AND c.alert_id=a.id
                AND c.opened_at<=clock.at AND (c.closed_at IS NULL OR c.closed_at>clock.at)
                AND s.start_at<=clock.at AND s.end_at>clock.at
                AND (s.deactivation_at IS NULL OR s.deactivation_at>clock.at))) AS derived_suppressed,
            coalesce(a.dismissed_until>(SELECT at FROM clock),false) AS dismissed
        FROM incident_alert_links l
        LEFT JOIN alert_identities ai ON ai.tenant_id=l.tenant_id AND ai.id=l.alert_id AND ai.retired_at IS NULL
        LEFT JOIN alerts a ON a.tenant_id=ai.tenant_id AND a.id=ai.id
        LEFT JOIN maintenance_alert_checkpoints cp ON cp.tenant_id=a.tenant_id AND cp.alert_id=a.id
        WHERE l.tenant_id=%s AND l.incident_id=ANY(%s::uuid[]) AND l.unlinked_at IS NULL)
        SELECT incident_id,count(*) AS total_linked,count(*) FILTER(WHERE id IS NULL) AS unavailable,
            count(*) FILTER(WHERE id IS NOT NULL AND (derived_suppressed OR dismissed)) AS suppressed,
            coalesce(bool_or(id IS NOT NULL AND complete IS DISTINCT FROM true),false) AS missing_proof,
            coalesce(bool_or(id IS NOT NULL AND (catalog_generation IS DISTINCT FROM %s OR
                stored_suppressed IS DISTINCT FROM derived_suppressed OR current_suppressed IS DISTINCT FROM derived_suppressed)),false) AS maintenance_updating
        FROM current_links GROUP BY incident_id""",
        (state["now"], tenant, [str(key) for key in incidents], state["maintenance_generation"]),
    ).fetchall()
    return {str(row.pop("incident_id")): row for row in rows}


def linked_counts(conn, tenant, incident):
    counts = _grouped(conn, tenant, [incident]).get(str(incident), dict(EMPTY))
    if counts.pop("missing_proof"):
        raise unavailable("maintenance_proof_unavailable")
    return counts


def page_linked_counts(conn, tenant, incidents):
    """Counts for a list page (REV-56); a row lacking maintenance proof has no suppressed count."""
    found = _grouped(conn, tenant, incidents) if incidents else {}
    result = {}
    for incident in incidents:
        counts = found.get(str(incident), EMPTY)
        result[str(incident)] = {
            "total_linked": counts["total_linked"],
            "suppressed": None if counts["missing_proof"] else counts["suppressed"],
            "unavailable": counts["unavailable"],
        }
    return result
