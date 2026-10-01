import hashlib
from datetime import UTC, datetime
from uuid import UUID

from psycopg.types.json import Jsonb

from appchi.ingestion.native import canonical
from appchi.shared.errors import AppError, unavailable


def wire(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("Authoritative timestamps require an explicit timezone")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {
            key: (
                str(item)
                if isinstance(item, int)
                and not isinstance(item, bool)
                and key not in {"x", "y", "w", "h", "index", "limit", "page_size", "window_minutes"}
                else wire(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [wire(item) for item in value]
    return value


def coordinator(conn, tenant):
    row = conn.execute(
        "SELECT * FROM tenant_work_state WHERE tenant_id=%s FOR UPDATE", (tenant,)
    ).fetchone()
    if row is None:
        raise AppError("not_found", "Resource unavailable.", 404)
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    if row["last_clock"] and now < row["last_clock"]:
        raise unavailable("clock_untrusted")
    conn.execute("UPDATE tenant_work_state SET last_clock=%s WHERE tenant_id=%s", (now, tenant))
    return row, now


def command_result(conn, scope, command_id, payload):
    # A transaction-level key prevents simultaneous identical commands on disjoint aggregates.
    conn.execute(
        "SELECT pg_advisory_xact_lock(%s)",
        (int.from_bytes(hashlib.sha256((scope + command_id).encode()).digest()[:8], signed=True),),
    )
    fingerprint = hashlib.sha256(canonical(payload)).digest()
    row = conn.execute(
        "SELECT * FROM command_receipts WHERE scope=%s AND command_id=%s", (scope, command_id)
    ).fetchone()
    if row:
        if bytes(row["fingerprint"]) != fingerprint:
            raise AppError(
                "idempotency_conflict", "Command identity was used with different content.", 409
            )
        expired_parent = command_parent_expired(conn, scope, command_id)
        from appchi.recovery.command_retention import expired as ordinary_command_expired

        if row["result"] is None or expired_parent or ordinary_command_expired(conn, row):
            raise AppError(
                "command_result_expired", "The original command result has expired.", 409
            )
        return row["result"], fingerprint
    return None, fingerprint


def command_parent_expired(conn, scope, command_id):
    return conn.execute(
        """SELECT 1 FROM command_resources r
        LEFT JOIN incident_identities i ON r.resource_kind='incident' AND i.tenant_id=r.tenant_id AND i.id=r.resource_id
        LEFT JOIN alert_identities a ON r.resource_kind='alert' AND a.tenant_id=r.tenant_id AND a.id=r.resource_id
        WHERE r.scope=%s AND r.command_id=%s AND (i.retired_at IS NOT NULL OR a.retired_at IS NOT NULL) LIMIT 1""",
        (scope, command_id),
    ).fetchone()


def save_result(conn, scope, command_id, fingerprint, result, status=200, *, resources=()):
    receipt = conn.execute(
        "INSERT INTO command_receipts(scope,command_id,fingerprint,result,status) VALUES(%s,%s,%s,%s,%s) RETURNING *",
        (scope, command_id, fingerprint, Jsonb(wire(result)), status),
    ).fetchone()
    for tenant, kind, resource in resources:
        conn.execute(
            "INSERT INTO command_resources(scope,command_id,tenant_id,resource_kind,resource_id) VALUES(%s,%s,%s,%s,%s)",
            (scope, command_id, tenant, kind, resource),
        )
    from appchi.recovery.command_retention import register

    register(conn, receipt)
    return wire(result)


def revision(row, expected):
    if row["revision"] != int(expected):
        raise AppError(
            "revision_conflict", "The resource changed. Refresh and review your draft.", 409
        )


def audit(conn, tenant, actor, kind, evidence):
    conn.execute(
        "INSERT INTO audit_events(tenant_id,actor_id,actor_label,kind,evidence) VALUES(%s,%s,%s,%s,%s)",
        (tenant, actor.get("id"), actor.get("display_name", "system"), kind, Jsonb(wire(evidence))),
    )
