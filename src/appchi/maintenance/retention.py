"""One dependency predicate for history reads and whole-timeline cleanup.

The caller binds the maintenance identity/window row as ``w``. Even a negative
evaluation needs its original segment until its retained source input is gone.
"""

DEPENDENCY_SQL = "maintenance_dependency_held(w.tenant_id,w.id)"

RETAINED_SQL = (
    """(NOT EXISTS(SELECT 1 FROM maintenance_content_retirements r
 WHERE r.tenant_id=w.tenant_id AND r.window_id=w.id) AND
 (w.deleted_at IS NULL OR w.deleted_at+interval '2160 hours'>clock_timestamp() OR """
    + DEPENDENCY_SQL
    + "))"
)


def dependency_held(conn, tenant, window):
    row = conn.execute(
        "SELECT "
        + DEPENDENCY_SQL
        + " AS held FROM maintenance_identities w WHERE tenant_id=%s AND id=%s",
        (tenant, window),
    ).fetchone()
    return bool(row and row["held"])


def history_retained(conn, row):
    result = conn.execute(
        "SELECT "
        + RETAINED_SQL
        + " AS retained FROM maintenance_windows w WHERE tenant_id=%s AND id=%s",
        (row["tenant_id"], row["id"]),
    ).fetchone()
    return bool(result and result["retained"])
