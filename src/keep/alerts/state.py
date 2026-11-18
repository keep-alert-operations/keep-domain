from keep.alerts.dismissal import dismissal_active, dismissal_view
from keep.alerts.presentation import display_status, present_command_result
from keep.cel.catalog import RULE_FIELDS
from keep.maintenance.runtime import apply_transition
from keep.maintenance.processing import derive_current
from keep.maintenance.temporal import MaintenanceProofError
from keep.shared.errors import AppError, unavailable
from keep.serialization import wire


def maintenance_adjust(conn, row, updated, now, cause, catalog):
    order = None
    if any(row.get(field) != updated.get(field) for field in RULE_FIELDS):
        order = conn.execute(
            "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
            (row["tenant_id"],),
        ).fetchone()["admission_order"]
    updated, changed, effects = apply_transition(
        conn, row, updated, now, order, cause, now, catalog
    )
    return updated, changed, effects, order


def with_current_assignee(conn, row):
    from keep.identity.cleanup import visible_assignee

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
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    try:
        suppressed, updating = derive_current(conn, row, now)
    except MaintenanceProofError:
        raise unavailable("maintenance_proof_unavailable") from None
    # A dismissal is evaluated against this read's clock (REV-49).
    dismissal = dismissal_view(row, now)
    if dismissal and dismissal["dismissed_by"] is not None:
        named = conn.execute(
            "SELECT display_name FROM principals WHERE id=%s", (dismissal["dismissed_by"],)
        ).fetchone()
        dismissal["dismissed_by_display_name"] = named["display_name"] if named else None
    return dict(
        row,
        suppressed=suppressed or dismissal_active(row, now),
        maintenance_updating=updating,
        dismissal=dismissal,
    )


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
