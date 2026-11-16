from psycopg.types.json import Jsonb

from keep.alerts.lifecycle import apply_source
from keep.alerts.repository import insert_alert_identity, publish, store_alert
from keep.observability import alert_fields, flow as alert_flow
from keep.observability.flow import seconds_since
from keep.shared.errors import AppError, unavailable
from keep.shared.transactions import coordinator


def process_one(db, tenant, attempt=None, profile=None):
    from keep.maintenance.runtime import prepare_for_tenant

    catalog = prepare_for_tenant(db, tenant, profile)
    with db.transaction(tenant) as conn:
        return _apply_one(conn, tenant, attempt, catalog)


def _apply_one(conn, tenant, attempt, catalog, *, supplied_item=None, coordinated=None):
    """Exact source transaction body, also used by rolled-back repair probes.

    No network, compilation or independent transaction belongs in this helper.
    The caller owns the outer transaction and precompiles its catalog. A caller
    already holding the tenant coordinator passes its (state, now) as coordinated.
    """
    from keep.maintenance.runtime import lock_catalog, apply_transition
    from keep.visibility.runtime import link_source_result

    state, now = coordinated or coordinator(conn, tenant)
    if supplied_item is None and (state["blocked"] or now < state["next_attempt_at"]):
        return False
    item = (
        supplied_item
        or conn.execute(
            "SELECT * FROM ingest_items WHERE tenant_id=%s AND disposition='pending' ORDER BY admission_order LIMIT 1 FOR UPDATE",
            (tenant,),
        ).fetchone()
    )
    if not item:
        return False
    if attempt is not None:
        attempt["item_id"] = item["id"]
    publication = None
    error_code = None
    claim = conn.execute(
        "SELECT * FROM alert_key_claims WHERE tenant_id=%s AND schema_version=%s AND key_digest=%s",
        (tenant, item["version"], item["key_digest"]),
    ).fetchone()
    lock_catalog(conn, catalog, targets=[claim["alert_id"]] if claim else [])
    previous = None
    linked = []
    if claim:
        from keep.incidents.state import lock_linked_incidents

        # lock_catalog already locked this alert's linked contexts.
        linked = lock_linked_incidents(conn, tenant, claim["alert_id"], contexts_locked=True)
        previous = conn.execute(
            "SELECT * FROM alerts WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant, claim["alert_id"]),
        ).fetchone()
    try:
        if claim and (
            claim["key_field"] != item["key_field"]
            or bytes(claim["identity_material"]) != bytes(item["identity_material"])
        ):
            raise AppError("identity_conflict", "Immutable identity material differs.", 409)
        current, changed = apply_source(previous, item)
    except AppError as error:
        error_code = error.code
        if supplied_item is None:
            conn.execute(
                "UPDATE ingest_items SET disposition='rejected',error_code=%s WHERE id=%s",
                (error.code, item["id"]),
            )
            conn.execute(
                "UPDATE ingest_retry_keys SET expires_at=%s + interval '90 days' WHERE item_id=%s",
                (item["received_at"], item["id"]),
            )
            link_source_result(conn, item, error_code=error.code)
        alert_flow.note(
            "alert_refused",
            learned={"alert": {"id": str(claim["alert_id"])}} if claim else None,
            alert=alert_fields(item["payload"], whole=True),
            error_code=error.code,
        )
    else:
        if previous is None:
            # Maintenance proof references the identity. Nothing in
            # apply_transition reads the alerts row, so store it once, final.
            insert_alert_identity(conn, current)
        current, changed, _ = apply_transition(
            conn,
            previous,
            current,
            item["received_at"],
            item["admission_order"],
            "source",
            now,
            catalog,
        )
        store_alert(conn, current, new=previous is None, identity_inserted=True)
        from keep.incidents.state import became_resolved, linked_transition

        linked_transition(conn, linked, previous, current, item["received_at"])
        if previous is None:
            conn.execute(
                "INSERT INTO alert_key_claims(tenant_id,schema_version,key_digest,key_field,identity_material,alert_id) VALUES(%s,%s,%s,%s,%s,%s)",
                (
                    tenant,
                    item["version"],
                    item["key_digest"],
                    item["key_field"],
                    item["identity_material"],
                    current["id"],
                ),
            )
        conn.execute(
            "INSERT INTO alert_source_events(tenant_id,alert_id,id,admission_order,received_at,payload,raw_json,time_defaulted,occurrence_id,adapter_version) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                tenant,
                current["id"],
                item["id"],
                item["admission_order"],
                item["received_at"],
                Jsonb(item["payload"]),
                item["raw_json"],
                item["time_defaulted"],
                current["occurrence_id"],
                # The column has no default; only Grafana events carry a version.
                item.get("adapter_version") or None,
            ),
        )
        if supplied_item is None:
            conn.execute(
                "UPDATE ingest_items SET disposition='applied',alert_id=%s,occurrence_id=%s,payload=NULL,raw_json=NULL WHERE id=%s",
                (current["id"], current["occurrence_id"], item["id"]),
            )
        publication = publish(
            conn,
            previous,
            current,
            item["received_at"],
            "source",
            semantic=changed,
            original_order=item["admission_order"],
            maintenance_input_recorded=True,
        )
        if became_resolved(previous, current):
            from keep.incidents.state import resolve_when_alerts_resolved

            resolve_when_alerts_resolved(conn, tenant, linked, now, catalog)
        # Held by the alert's flow and written once this transaction commits.
        alert_flow.note(
            "alert_applied",
            learned={
                "alert": {"id": str(current["id"])},
                "changed_event_id": publication["event_id"],
            },
            alert=alert_fields(item["payload"], whole=True, provider=current.get("provider")),
            outcome=source_outcome(previous, current, changed),
            status_before=previous["status"] if previous else "none",
            status_after=current["status"],
            revision=current["revision"],
            suppressed=bool(current.get("suppressed")),
            projection_seq=publication["projection_seq"],
            # Receipt to PostgreSQL commit: read when the step is written.
            delay_seconds=lambda: seconds_since(item["received_at"]),
        )
        if supplied_item is None:
            link_source_result(
                conn,
                item,
                before=previous,
                after=current,
                publication=publication,
                changed=changed,
            )
    if supplied_item is not None:
        return {
            "alert_id": current["id"] if not error_code else None,
            "error_code": error_code,
            "envelope": publication["envelope"] if publication else None,
            "event_id": publication["event_id"] if publication else None,
        }
    conn.execute("UPDATE tenant_work_state SET failures=0 WHERE tenant_id=%s", (tenant,))
    conn.execute(
        "UPDATE application_outbox SET processed_at=%s WHERE tenant_id=%s AND stream='received' AND stream_order=%s",
        (now, tenant, item["admission_order"]),
    )
    release_reservation(conn, tenant, item["id"])
    return True


def source_outcome(previous, current, changed):
    """What a delivered input did to its alert, in one word."""
    if previous is None:
        return "created"
    if previous["status"] != current["status"]:
        return "resolved" if current["status"] == "resolved" else "reopened"
    return "updated" if changed else "unchanged"


def release_reservation(conn, tenant, item_id):
    reservation = conn.execute(
        "SELECT * FROM admission_reservations WHERE item_id=%s", (item_id,)
    ).fetchone()
    if not reservation or reservation["released"]:
        raise unavailable("capacity_accounting_mismatch")
    for scope in ("global", str(tenant)):
        conn.execute(
            "SELECT scope FROM admission_capacity WHERE scope=%s FOR UPDATE", (scope,)
        ).fetchone()
    conn.execute(
        "UPDATE admission_reservations SET released=true WHERE item_id=%s AND NOT released",
        (item_id,),
    )
    for scope in ("global", str(tenant)):
        conn.execute(
            "UPDATE admission_capacity SET pending_items=pending_items-1,pending_bytes=pending_bytes-%s WHERE scope=%s",
            (reservation["bytes"], scope),
        )


def record_failure(db, tenant, item_id):
    with db.transaction(tenant) as conn:
        coordinator(conn, tenant)
        head = conn.execute(
            "SELECT id FROM ingest_items WHERE tenant_id=%s AND disposition='pending' ORDER BY admission_order LIMIT 1",
            (tenant,),
        ).fetchone()
        if not head or head["id"] != item_id:
            return
        conn.execute(
            "UPDATE tenant_work_state SET failures=failures+1,blocked=(failures+1>=10),block_generation=block_generation+CASE WHEN failures+1=10 THEN 1 ELSE 0 END,next_attempt_at=clock_timestamp()+make_interval(secs=>random()*least(30,power(2,least(failures,5)))::int) WHERE tenant_id=%s",
            (tenant,),
        )
