"""Transactional maintenance configuration and durable temporal control proof."""

from dataclasses import asdict
from datetime import datetime
import hashlib
from uuid import uuid4

from psycopg.types.json import Jsonb

from appchi.ingestion.native import canonical
from appchi.shared.capacity import budget
from appchi.shared.errors import AppError
from appchi.serialization import wire

from .temporal import (
    Boundary,
    MaintenanceConflict,
    Segment,
    WindowState,
    change_window,
    revise_segments,
)
from .timezones import (
    ConvertedEndpoint,
    ScheduleError,
    local_to_utc,
    render_endpoint,
    validate_schedule,
    zone,
)


def get_window(conn, tenant, window, *, lock=False, include_deleted=False):
    row = conn.execute(
        "SELECT * FROM maintenance_windows WHERE tenant_id=%s AND id=%s"
        + ("" if include_deleted else " AND deleted_at IS NULL")
        + (" FOR UPDATE" if lock else ""),
        (tenant, window),
    ).fetchone()
    if not row:
        raise AppError("not_found", "Maintenance window unavailable.", 404)
    return row


def endpoint(value):
    return ConvertedEndpoint(
        value["timezone"],
        value["local"],
        datetime.fromisoformat(value["utc"]),
        int(value["offset_seconds"]),
        value["occurrence"],
        value["tzdata_version"],
    )


def state(row):
    return WindowState(
        row["start_at"],
        row["end_at"],
        row["cel_digest"],
        row["enabled"],
        row["started_lock"],
        bool(row["deleted_at"]),
        row["revision"],
    )


def public(row, now):
    data = {
        key: row[key]
        for key in (
            "id",
            "tenant_id",
            "revision",
            "name",
            "reason",
            "cel",
            "profile",
            "start_at",
            "end_at",
            "timezone",
            "enabled",
            "deleted_at",
            "processing_health",
            "created_at",
            "updated_at",
        )
    }
    data["phase"] = state(row).phase(now)
    data["started_lock"] = row["started_lock"] or now >= row["start_at"]
    data["schedule_evidence"] = row["schedule_evidence"]
    data["start_display"] = render_endpoint(
        endpoint(row["schedule_evidence"]["start"]), row["timezone"]
    )
    data["end_display"] = render_endpoint(
        endpoint(row["schedule_evidence"]["end"]), row["timezone"]
    )
    return wire(data)


def candidate(body, now, previous=None):
    """Schedule conversion must be rechecked against locked database action time."""
    try:
        if previous is None:
            start = local_to_utc(body.timezone, body.start_local, body.start_occurrence)
            end = local_to_utc(body.timezone, body.end_local, body.end_occurrence)
            validate_schedule(start, end, now)
            return {
                "name": body.name,
                "reason": body.reason,
                "cel": body.cel,
                "timezone": body.timezone,
                "start_at": start.utc,
                "end_at": end.utc,
                "schedule_evidence": wire({"start": asdict(start), "end": asdict(end)}),
            }
        result = {
            key: previous[key]
            for key in (
                "name",
                "reason",
                "cel",
                "timezone",
                "start_at",
                "end_at",
                "schedule_evidence",
            )
        }
        if body.kind == "metadata":
            for key in ("name", "reason"):
                if key in body.model_fields_set:
                    result[key] = getattr(body, key)
        elif body.kind == "timezone":
            zone(body.timezone)
            result["timezone"] = body.timezone
        else:
            selected = body.timezone or previous["timezone"]
            zone(selected)
            result["timezone"] = selected
            result["schedule_evidence"] = {**previous["schedule_evidence"]}
            for key in ("start", "end"):
                local = getattr(body, key + "_local")
                if local is not None:
                    converted = local_to_utc(selected, local, getattr(body, key + "_occurrence"))
                    result[key + "_at"] = converted.utc
                    result["schedule_evidence"][key] = wire(asdict(converted))
            if body.cel is not None:
                result["cel"] = body.cel
        return result
    except ScheduleError as exc:
        raise AppError(
            exc.code,
            str(exc),
            422,
            fields=[{"candidates": list(exc.candidates)}] if exc.candidates else None,
        ) from None


def check_capacity(conn, tenant, candidate, profile, now, window=None):
    """Each unset maintenance budget is unlimited (REV-39)."""
    limits = (profile or {}).get("maintenance")
    max_overlap, max_bytes = budget(limits, "max_overlap"), budget(limits, "max_work_bytes")
    rows = conn.execute(
        "SELECT id,start_at,end_at,cel,reason FROM maintenance_windows WHERE tenant_id=%s AND deleted_at IS NULL AND end_at>%s AND id<>%s",
        (tenant, now, window or uuid4()),
    ).fetchall()
    rows.append(candidate)
    points = []
    for row in rows:
        if row["end_at"] > now:
            points.extend(((max(now, row["start_at"]), 1), (row["end_at"], -1)))
    overlap = 0
    for _, delta in sorted(points):
        overlap += delta
        if overlap > max_overlap:
            raise AppError(
                "maintenance_capacity_exceeded", "Overlapping schedule capacity is exhausted.", 409
            )
    bytes_used = sum(len(row["cel"].encode()) + len(row["reason"].encode()) for row in rows)
    if bytes_used > max_bytes:
        raise AppError(
            "maintenance_capacity_exceeded", "Maintenance definition capacity is exhausted.", 409
        )


def _segments(conn, tenant, window, program):
    rows = conn.execute(
        "SELECT * FROM maintenance_segments WHERE tenant_id=%s AND window_id=%s ORDER BY activation_at,activation_order,id FOR UPDATE",
        (tenant, window),
    ).fetchall()
    result = []
    for row in rows:
        end_revisions = tuple(
            (
                Boundary(datetime.fromisoformat(v["at"]), int(v["order"]), v["id"]),
                datetime.fromisoformat(v["end"]),
            )
            for v in row["end_revisions"]
        )
        result.append(
            Segment(
                row["id"],
                row["window_id"],
                row["expression_revision"],
                Boundary(row["activation_at"], row["activation_order"], str(row["activation_id"])),
                row["start_at"],
                row["end_at"],
                program,
                Boundary(
                    row["deactivation_at"], row["deactivation_order"], str(row["deactivation_id"])
                )
                if row["deactivation_id"]
                else None,
                end_revisions,
            )
        )
    return tuple(result)


def persist(
    conn,
    tenant,
    actor,
    now,
    definition,
    program,
    *,
    previous=None,
    enabled=None,
    deleted=False,
    action="create",
    profile=None,
):
    window = previous["id"] if previous else uuid4()
    digest = hashlib.sha256(definition["cel"].encode()).hexdigest()
    try:
        next_state = (
            change_window(
                state(previous),
                action_time=now,
                start=definition["start_at"],
                end=definition["end_at"],
                cel_digest=digest,
                enabled=enabled,
                delete=deleted,
            )
            if previous
            else WindowState(
                definition["start_at"],
                definition["end_at"],
                digest,
                started_lock=now >= definition["start_at"],
            )
        )
    except MaintenanceConflict as exc:
        raise AppError(
            exc.code, "The maintenance schedule can no longer be changed this way.", 409
        ) from None
    same = (
        previous
        and all(previous[key] == value for key, value in definition.items())
        and next_state.enabled == previous["enabled"]
        and not deleted
    )
    if same:
        return previous, False
    rev = previous["revision"] + 1 if previous else 1
    next_state = WindowState(
        next_state.start,
        next_state.end,
        next_state.cel_digest,
        next_state.enabled,
        next_state.started_lock,
        next_state.deleted,
        rev,
    )
    coverage = (
        not previous
        or any(previous[key] != definition[key] for key in ("cel", "start_at", "end_at"))
        or next_state.enabled != previous["enabled"]
        or deleted
    )
    if not previous:
        conn.execute(
            "INSERT INTO maintenance_identities(id,tenant_id) VALUES(%s,%s)", (window, tenant)
        )
    health = "healthy"
    conn.execute(
        """INSERT INTO maintenance_windows(id,tenant_id,revision,name,name_key,reason,cel,profile,cel_digest,start_at,end_at,timezone,schedule_evidence,
        enabled,started_lock,deleted_at,processing_health,created_at,updated_at,created_by,updated_by)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,name=EXCLUDED.name,name_key=EXCLUDED.name_key,reason=EXCLUDED.reason,
        cel=EXCLUDED.cel,cel_digest=EXCLUDED.cel_digest,start_at=EXCLUDED.start_at,end_at=EXCLUDED.end_at,timezone=EXCLUDED.timezone,
        schedule_evidence=EXCLUDED.schedule_evidence,enabled=EXCLUDED.enabled,started_lock=EXCLUDED.started_lock,deleted_at=EXCLUDED.deleted_at,
        processing_health=EXCLUDED.processing_health,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by""",
        (
            window,
            tenant,
            rev,
            definition["name"],
            definition["name"].casefold(),
            definition["reason"],
            definition["cel"],
            program.profile,
            digest,
            definition["start_at"],
            definition["end_at"],
            definition["timezone"],
            Jsonb(definition["schedule_evidence"]),
            next_state.enabled,
            next_state.started_lock,
            now if deleted else None,
            health,
            previous["created_at"] if previous else now,
            now,
            previous["created_by"] if previous else actor["id"],
            actor["id"],
        ),
    )
    progress = conn.execute(
        """UPDATE tenant_view_state SET resource_generation=resource_generation+1,view_generation=view_generation+1,
                         maintenance_generation=maintenance_generation+%s WHERE tenant_id=%s RETURNING *""",
        (int(coverage), tenant),
    ).fetchone()
    if coverage:
        order = conn.execute(
            "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
            (tenant,),
        ).fetchone()["admission_order"]
        control_id = uuid4()
        conn.execute(
            "INSERT INTO maintenance_controls(id,tenant_id,window_id,revision,effective_at,tenant_order,kind,generation) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                control_id,
                tenant,
                window,
                rev,
                now,
                order,
                action,
                progress["maintenance_generation"],
            ),
        )
        boundary = Boundary(now, order, str(control_id))
        before_segments = _segments(conn, tenant, window, program)
        after_segments = revise_segments(
            window,
            state(previous) if previous else None,
            next_state,
            before_segments,
            boundary,
            program,
        )
        for segment in after_segments:
            conn.execute(
                """INSERT INTO maintenance_segments(id,tenant_id,window_id,expression_revision,cel,profile,cel_digest,start_at,end_at,
                         activation_id,activation_at,activation_order,deactivation_id,deactivation_at,deactivation_order,end_revisions,generation)
                         VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                         ON CONFLICT(id) DO UPDATE SET end_at=EXCLUDED.end_at,deactivation_id=EXCLUDED.deactivation_id,
                         deactivation_at=EXCLUDED.deactivation_at,deactivation_order=EXCLUDED.deactivation_order,end_revisions=EXCLUDED.end_revisions,generation=EXCLUDED.generation""",
                (
                    segment.id,
                    tenant,
                    window,
                    segment.expression_revision,
                    definition["cel"],
                    program.profile,
                    digest,
                    segment.start,
                    segment.end,
                    segment.activation.id,
                    segment.activation.at,
                    segment.activation.order,
                    segment.deactivation.id if segment.deactivation else None,
                    segment.deactivation.at if segment.deactivation else None,
                    segment.deactivation.order if segment.deactivation else None,
                    Jsonb(
                        wire(
                            [
                                {"at": b.at, "order": b.order, "id": b.id, "end": end}
                                for b, end in segment.end_revisions
                            ]
                        )
                    ),
                    progress["maintenance_generation"],
                ),
            )
        # Coverage proof remains durable; timer/control fan-out is deferred.
    row = get_window(conn, tenant, window, include_deleted=True)
    snapshot = public(row, now)
    conn.execute(
        "INSERT INTO maintenance_revisions(tenant_id,window_id,revision,snapshot,action,recorded_at,actor_id,actor_label) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
        (tenant, window, rev, Jsonb(snapshot), action, now, actor["id"], actor["display_name"]),
    )
    envelope = canonical(
        wire(
            {
                "version": 1,
                "tenant_id": tenant,
                "resource_kind": "maintenance",
                "resource_id": window,
                "revision": rev,
                "resource_generation": progress["resource_generation"],
                "maintenance_generation": progress["maintenance_generation"],
            }
        )
    )
    conn.execute(
        "INSERT INTO application_outbox(id,tenant_id,stream,stream_order,envelope) VALUES(%s,%s,%s,%s,%s)",
        (uuid4(), tenant, "resource:maintenance:" + str(window), rev, envelope),
    )
    if deleted:
        conn.execute(
            "UPDATE maintenance_identities SET deleted_at=%s,final_revision=%s WHERE tenant_id=%s AND id=%s",
            (now, rev, tenant, window),
        )
    return row, True
