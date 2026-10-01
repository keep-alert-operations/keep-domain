"""Explicit server capture profile; capture is not rendered SLI qualification."""

from uuid import UUID, uuid5

from .inputs import record_input, registry_checkpoint, link_application
from .profile import CaptureProfile as CaptureProfile, capture_profile as capture_profile






def record_admission(conn, *, tenant, item_id, received_at, admission_order, profile):
    configured = capture_profile(profile)
    if configured is None:
        return {"status": "disabled"}
    # Called inside the already locked admission transaction. Capacity exhaustion
    # records an explicit coverage gap, not a fabricated empty observation cohort.
    return record_input(
        conn,
        tenant=tenant,
        input_id=UUID(str(item_id)),
        kind="incoming",
        started_at=received_at,
        original_order=admission_order,
        registry_checkpoint=registry_checkpoint(conn, tenant),
        policy=configured.policy,
        limits=configured.inputs,
    )


def link_source_result(
    conn, item, *, before=None, after=None, publication=None, changed=False, error_code=None
):
    """Resume a captured input using its persisted policy even after reconfiguration."""
    # Unconfigured deployments and hard input-capacity gaps have no seed. Never
    # fabricate one after processing: that would lose the original denominator.
    seed = conn.execute(
        "SELECT 1 FROM visibility_inputs WHERE tenant_id=%s AND id=%s",
        (item["tenant_id"], item["id"]),
    ).fetchone()
    if not seed:
        return {"status": "seed_unavailable"}
    if error_code is not None:
        return link_application(
            conn,
            tenant=item["tenant_id"],
            input_id=item["id"],
            application_id=item["id"],
            alert_id=None,
            before=None,
            after=None,
            projection_seq=None,
            projection_version=None,
            disposition="rejected",
            error_code=error_code,
        )
    return link_application(
        conn,
        tenant=item["tenant_id"],
        input_id=item["id"],
        application_id=item["id"],
        alert_id=after["id"],
        before=before,
        after=after,
        projection_seq=publication["projection_seq"],
        projection_version=after["projection_version"],
        journal_order=publication["change_order"] if changed else None,
        source_event_id=item["id"],
        disposition="applied" if changed else "unchanged",
    )


def capture_turn(db):
    """Seal one due boundary and expand one bounded page using persisted limits."""
    from appchi.recovery.incidents import ready
    from .inputs import seal_expiry_boundary, expand_next

    with db.transaction() as conn:
        ready(conn)
        seed = conn.execute(
            """SELECT i.tenant_id,i.id FROM visibility_inputs i
            JOIN tenant_work_state w ON w.tenant_id=i.tenant_id
            WHERE i.kind='maintenance_expiry' AND i.disposition='pending'
            AND i.cohort_checkpoint IS NULL AND i.started_at<=clock_timestamp()
            ORDER BY i.started_at,i.tenant_id,i.id LIMIT 1 FOR UPDATE OF w SKIP LOCKED"""
        ).fetchone()
        if seed:
            seal_expiry_boundary(conn, tenant=seed["tenant_id"], input_id=seed["id"])
    with db.transaction() as conn:
        ready(conn)
        return expand_next(conn)


def link_expiry_result(conn, job, *, before, after, changed):
    """Link a completed fanout step without extending the product proof lifetime.

    A later reducer state is allowed evidence of materialization, never proof of
    what was rendered or of query membership at the original scheduled end.
    """
    if job["kind"] != "scheduled_end":
        return {"status": "not_expiry"}
    seed = conn.execute(
        "SELECT 1 FROM visibility_inputs WHERE tenant_id=%s AND id=%s AND disposition='pending'",
        (job["tenant_id"], job["id"]),
    ).fetchone()
    if not seed:
        return {"status": "seed_unavailable"}
    projection = conn.execute(
        """SELECT seq FROM projection_work WHERE tenant_id=%s AND alert_id=%s AND version=%s""",
        (job["tenant_id"], after["id"], after["projection_version"]),
    ).fetchone()
    if not projection:
        conn.execute(
            "UPDATE visibility_inputs SET application_gap='projection_proof_unavailable' WHERE tenant_id=%s AND id=%s",
            (job["tenant_id"], job["id"]),
        )
        return {"status": "proof_gap"}
    return link_application(
        conn,
        tenant=job["tenant_id"],
        input_id=job["id"],
        application_id=uuid5(job["id"], "expiry-alert:" + str(after["id"])),
        alert_id=after["id"],
        before=before,
        after=after,
        projection_seq=projection["seq"],
        projection_version=after["projection_version"],
        disposition="applied" if changed else "unchanged",
    )
