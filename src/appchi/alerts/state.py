from appchi.alerts.presentation import display_status, present_command_result
from appchi.cel.catalog import RULE_FIELDS
from appchi.maintenance.runtime import apply_transition
from appchi.maintenance.processing import derive_current
from appchi.maintenance.temporal import MaintenanceProofError
from appchi.shared.errors import AppError, unavailable
from appchi.serialization import wire


def maintenance_adjust(conn, row, updated, now, cause, catalog):
    order = None
    if any(row[field] != updated[field] for field in RULE_FIELDS):
        order = conn.execute(
            "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
            (row["tenant_id"],),
        ).fetchone()["admission_order"]
    updated, changed, effects = apply_transition(
        conn, row, updated, now, order, cause, now, catalog
    )
    return updated, changed, effects, order


def with_current_assignee(conn, row):
    from appchi.identity.cleanup import visible_assignee

    assignee_id, pending_cleanup = visible_assignee(conn, row["tenant_id"], row.get("assignee_id"))
    return dict(row, assignee_id=assignee_id, assignment_cleanup_pending=pending_cleanup)


def current_command_result(conn, result):
    # Current eligibility masks response presentation, never the immutable receipt.
    data = result["data"]
    rows = data if isinstance(data, list) else [data]
    visible = [wire(with_current_assignee(conn, row)) for row in rows]
    return present_command_result(
        {**result, "data": visible if isinstance(data, list) else visible[0]}
    )


def derived_read(conn, row):
    row = with_current_assignee(conn, row)
    row = dict(row, display_status=display_status(row))
    gate = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='maintenance'"
    ).fetchone()
    if gate and gate["ready"]:
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        try:
            suppressed, updating = derive_current(conn, row, now)
        except MaintenanceProofError:
            raise unavailable("maintenance_proof_unavailable") from None
        return dict(row, suppressed=suppressed, maintenance_updating=updating)
    if conn.execute(
        "SELECT 1 FROM maintenance_segments WHERE tenant_id=%s LIMIT 1", (row["tenant_id"],)
    ).fetchone():
        raise unavailable("maintenance_gate_closed_with_timeline")
    return row


def retained(conn, tenant, alert_id, lock=False):
    row = conn.execute(
        "SELECT a.* FROM alerts a JOIN alert_identities i ON i.id=a.id AND i.tenant_id=a.tenant_id WHERE a.tenant_id=%s AND a.id=%s AND i.retired_at IS NULL"
        + (" FOR UPDATE OF a" if lock else ""),
        (tenant, alert_id),
    ).fetchone()
    if row is None:
        raise AppError("not_found", "Alert unavailable.", 404)
    return row


def pending(conn, tenant, row):
    """Compatibility call site: queued Kafka source work does not block commands."""
