"""Exact retained-link counts with authoritative suppression at one DB clock."""

from appchi.shared.errors import unavailable


def linked_counts(conn, tenant, incident):
    state = conn.execute(
        """SELECT maintenance_generation,clock_timestamp() AS now
        FROM tenant_view_state WHERE tenant_id=%s""",
        (tenant,),
    ).fetchone()
    counts = conn.execute(
        """WITH clock AS (SELECT %s::timestamptz AS at), current_links AS (
        SELECT a.id,a.suppressed AS stored_suppressed,cp.complete,cp.catalog_generation,
            cp.current_suppressed,
            (coalesce(a.source_suppressed,false) OR EXISTS(
                SELECT 1 FROM alert_maintenance_causes c JOIN maintenance_segments s
                ON s.tenant_id=c.tenant_id AND s.id=c.segment_id CROSS JOIN clock
                WHERE c.tenant_id=a.tenant_id AND c.alert_id=a.id
                AND c.opened_at<=clock.at AND (c.closed_at IS NULL OR c.closed_at>clock.at)
                AND s.start_at<=clock.at AND s.end_at>clock.at
                AND (s.deactivation_at IS NULL OR s.deactivation_at>clock.at))) AS derived_suppressed
        FROM incident_alert_links l
        LEFT JOIN alert_identities ai ON ai.tenant_id=l.tenant_id AND ai.id=l.alert_id AND ai.retired_at IS NULL
        LEFT JOIN alerts a ON a.tenant_id=ai.tenant_id AND a.id=ai.id
        LEFT JOIN maintenance_alert_checkpoints cp ON cp.tenant_id=a.tenant_id AND cp.alert_id=a.id
        WHERE l.tenant_id=%s AND l.incident_id=%s AND l.unlinked_at IS NULL)
        SELECT count(*) AS total_linked,count(*) FILTER(WHERE id IS NULL) AS unavailable,
            count(*) FILTER(WHERE id IS NOT NULL AND derived_suppressed) AS suppressed,
            coalesce(bool_or(id IS NOT NULL AND complete IS DISTINCT FROM true),false) AS missing_proof,
            coalesce(bool_or(id IS NOT NULL AND (catalog_generation IS DISTINCT FROM %s OR
                stored_suppressed IS DISTINCT FROM derived_suppressed OR current_suppressed IS DISTINCT FROM derived_suppressed)),false) AS maintenance_updating
        FROM current_links""",
        (state["now"], tenant, incident, state["maintenance_generation"]),
    ).fetchone()
    if counts.pop("missing_proof"):
        raise unavailable("maintenance_proof_unavailable")
    return counts
