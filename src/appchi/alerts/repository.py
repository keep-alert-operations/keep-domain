from uuid import uuid4
from psycopg import sql
from psycopg.types.json import Jsonb

from appchi.serialization import wire


def store_alert(conn, current, new=False):
    if new:
        conn.execute(
            "INSERT INTO alert_identities(id,tenant_id) VALUES(%s,%s)",
            (current["id"], current["tenant_id"]),
        )
        columns = list(current)
        query = sql.SQL("INSERT INTO alerts ({}) VALUES ({})").format(
            sql.SQL(",").join(map(sql.Identifier, columns)),
            sql.SQL(",").join(sql.Placeholder() * len(columns)),
        )
        conn.execute(query, list(current.values()))
    else:
        columns = [key for key in current if key not in ("id", "tenant_id")]
        query = sql.SQL("UPDATE alerts SET {} WHERE id=%s AND tenant_id=%s").format(
            sql.SQL(",").join(sql.SQL("{}=%s").format(sql.Identifier(key)) for key in columns)
        )
        conn.execute(
            query, [current[key] for key in columns] + [current["id"], current["tenant_id"]]
        )


def publish(
    conn,
    before,
    after,
    when,
    cause,
    *,
    semantic=True,
    original_order=None,
    actor=None,
    maintenance_input_recorded=False,
    activity_evidence=None,
):
    tenant = after["tenant_id"]
    state = conn.execute(
        "UPDATE tenant_work_state SET change_order=change_order+%s,projection_seq=projection_seq+1 WHERE tenant_id=%s RETURNING change_order,projection_seq",
        (int(semantic), tenant),
    ).fetchone()
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    if cause != "source" and before is not None:
        if before["status"] != "resolved" and after["status"] == "resolved":
            from appchi.correlation.runtime import release_alert

            release_alert(conn, tenant, after["id"], now)
        elif after["suppressed"]:
            conn.execute(
                "DELETE FROM correlation_evidence WHERE tenant_id=%s AND alert_id=%s",
                (tenant, after["id"]),
            )
        else:
            # Ignored edits do not make live evidence stale solely by revision.
            conn.execute(
                "UPDATE correlation_evidence SET observed_revision=%s WHERE tenant_id=%s AND alert_id=%s AND observed_revision=%s",
                (after["revision"], tenant, after["id"], before["revision"]),
            )
    from appchi.cel.catalog import RULE_FIELDS
    from appchi.maintenance.processing import record_input

    if not maintenance_input_recorded and (
        cause == "source"
        or before is None
        or any(before[field] != after[field] for field in RULE_FIELDS)
    ):
        if original_order is None:
            original_order = conn.execute(
                "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
                (tenant,),
            ).fetchone()["admission_order"]
        record_input(conn, before, after, when, original_order, cause, now)
    if semantic:
        actor_row = (
            conn.execute("SELECT display_name FROM principals WHERE id=%s", (actor,)).fetchone()
            if actor is not None
            else None
        )
        conn.execute(
            "INSERT INTO alert_activity(tenant_id,alert_id,id,change_order,recorded_at,effective_at,actor_id,kind,evidence,actor_display_name) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                tenant,
                after["id"],
                uuid4(),
                state["change_order"],
                now,
                when,
                actor,
                cause,
                Jsonb(
                    {
                        "before": wire(before),
                        "after": wire(after),
                        **(
                            {"context": wire(activity_evidence)}
                            if activity_evidence is not None
                            else {}
                        ),
                    }
                ),
                actor_row["display_name"] if actor_row else None,
            ),
        )
        conn.execute(
            "INSERT INTO correlation_journal(tenant_id,change_order,alert_id,before_snapshot,after_snapshot,original_order,effective_at,cause) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                tenant,
                state["change_order"],
                after["id"],
                Jsonb(wire(before)),
                Jsonb(wire(after)),
                original_order,
                when,
                cause,
            ),
        )
    if after["occurrence_id"]:
        conn.execute(
            "INSERT INTO alert_occurrences(tenant_id,alert_id,id,number,opened_at,resolved_at,time_created) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(alert_id,id) DO UPDATE SET resolved_at=EXCLUDED.resolved_at",
            (
                tenant,
                after["id"],
                after["occurrence_id"],
                after["occurrence_number"],
                after["opened_at"],
                after["resolved_at"],
                after["time_created"],
            ),
        )
    snapshot = wire(after)
    snapshot["live"] = True
    snapshot["last_received_at"] = snapshot["timestamp"]
    snapshot["notes"] = [
        row["text"]
        for row in conn.execute(
            "SELECT text FROM alert_notes WHERE tenant_id=%s AND alert_id=%s AND NOT deleted ORDER BY id",
            (tenant, after["id"]),
        )
    ]
    snapshot["incident_ids"] = [
        str(row["incident_id"])
        for row in conn.execute(
            "SELECT incident_id FROM incident_alert_links WHERE tenant_id=%s AND alert_id=%s AND unlinked_at IS NULL ORDER BY incident_id",
            (tenant, after["id"]),
        )
    ]
    owner = conn.execute(
        "SELECT incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
        (tenant, after["id"]),
    ).fetchone()
    snapshot["active_incident_id"] = str(owner["incident_id"]) if owner else None
    conn.execute(
        "INSERT INTO projection_work(tenant_id,seq,alert_id,version,snapshot) VALUES(%s,%s,%s,%s,%s)",
        (
            tenant,
            state["projection_seq"],
            after["id"],
            after["projection_version"],
            Jsonb(snapshot),
        ),
    )
    from appchi.events import changed

    envelope = changed(
        tenant=tenant,
        alert=after["id"],
        seq=state["projection_seq"],
        version=after["projection_version"],
        snapshot=snapshot,
        change_order=state["change_order"],
        cause=cause,
        effective_at=when,
        recorded_at=now,
        actor=actor,
        original_order=original_order,
    )
    conn.execute(
        "UPDATE alert_identities SET current_projection_seq=%s WHERE tenant_id=%s AND id=%s",
        (state["projection_seq"], tenant, after["id"]),
    )
    if cause != "source":
        from appchi.alert_notifications import remember

        remember(envelope)
    conn.execute(
        "UPDATE tenant_view_state SET view_generation=view_generation+1 WHERE tenant_id=%s",
        (tenant,),
    )
    from appchi.maintenance.runtime import publish_inline_effects

    publish_inline_effects(conn, after)
    return {**state, "envelope": envelope}
