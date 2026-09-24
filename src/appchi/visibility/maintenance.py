"""Maintenance schedule producers; no application or rendered-success proof."""

from appchi.shared.errors import AppError

from .inputs import dispose_schedule, record_input, registry_checkpoint
from .runtime import capture_profile


def record_scheduled_end(conn, job, *, revision, profile):
    """Capture beside the committed scheduled job while its coordinator is held."""
    configured = capture_profile(profile)
    if configured is None:
        return {"status": "disabled"}
    return record_input(
        conn,
        tenant=job["tenant_id"],
        input_id=job["id"],
        kind="maintenance_expiry",
        started_at=job["expected_end"],
        original_order=0,
        registry_checkpoint=registry_checkpoint(conn, job["tenant_id"]),
        policy=configured.policy,
        limits=configured.inputs,
        schedule={
            "window_id": str(job["window_id"]),
            "revision": revision,
            "generation": job["generation"],
        },
    )


def dispose_replaced_end(conn, job, *, control_id, cancelled):
    """Preserve due observations, and dispose captured future work without config.

    The caller just obsoleted this job beside its new immutable control. No new
    capture profile is needed to finish the old seed's lifecycle. A boundary
    crossed during the transaction stays unclassified instead of being erased or
    causing an otherwise valid maintenance control to roll back.
    """
    seed = conn.execute(
        "SELECT kind,started_at,schedule FROM visibility_inputs WHERE tenant_id=%s AND id=%s",
        (job["tenant_id"], job["id"]),
    ).fetchone()
    if not seed:
        return {"status": "seed_unavailable"}
    if (
        seed["kind"] != "maintenance_expiry"
        or job["kind"] != "scheduled_end"
        or seed["schedule"]["window_id"] != str(job["window_id"])
        or seed["started_at"] != job["expected_end"]
    ):
        raise ValueError("Scheduled job differs from its captured original boundary")
    try:
        row = dispose_schedule(
            conn,
            tenant=job["tenant_id"],
            input_id=job["id"],
            # Claiming a due end advances the mutable job's generation. Only the
            # seed retains the original schedule generation used by disposition.
            generation=seed["schedule"]["generation"],
            disposition="cancelled" if cancelled else "superseded",
            evidence_reference="maintenance-control:" + str(control_id),
        )
    except AppError as error:
        if error.code != "visibility_boundary_passed":
            raise
        return {"status": "due_preserved"}
    return {"status": row["disposition"]}
