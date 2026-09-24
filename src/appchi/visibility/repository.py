"""Registry persistence. Caller holds identity guard and tenant coordinator."""

from datetime import datetime

from psycopg.types.json import Jsonb

from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import wire


def get_view(conn, tenant, view_id, session_hash, deployment_epoch):
    row = conn.execute(
        """SELECT * FROM visibility_views WHERE tenant_id=%s AND id=%s
        AND session_hash=%s AND deployment_epoch=%s""",
        (tenant, view_id, session_hash, deployment_epoch),
    ).fetchone()
    if row is None:
        raise AppError("not_found", "View registration unavailable.", 404)
    return row


def replay(conn, tenant, session_hash, command_id, fingerprint):
    row = conn.execute(
        """SELECT fingerprint,response FROM visibility_view_controls
        WHERE tenant_id=%s AND session_hash=%s AND command_id=%s""",
        (tenant, session_hash, command_id),
    ).fetchone()
    if row:
        if bytes(row["fingerprint"]) != fingerprint:
            raise AppError("idempotency_conflict", "Command identity has different content.", 409)
        return row["response"]
    return None


def next_checkpoint(conn, tenant, maximum):
    conn.execute(
        "INSERT INTO visibility_registry_heads(tenant_id) VALUES(%s) ON CONFLICT DO NOTHING",
        (tenant,),
    )
    row = conn.execute(
        """UPDATE visibility_registry_heads SET checkpoint=checkpoint+1
        WHERE tenant_id=%s AND checkpoint<%s RETURNING checkpoint""",
        (tenant, maximum),
    ).fetchone()
    if not row:
        raise unavailable("visibility_registry_capacity")
    return row["checkpoint"]


def check_view_capacity(conn, tenant, session_hash, deployment_epoch, now, limits):
    for maximum, extra, params in (
        (limits.max_active_tenant_views, "", ()),
        (
            limits.max_active_session_views,
            "AND session_hash=%s AND deployment_epoch=%s",
            (session_hash, deployment_epoch),
        ),
    ):
        full = (
            conn.execute(
                f"""SELECT count(*) AS n FROM (
              SELECT 1 FROM visibility_views WHERE tenant_id=%s
              AND state<>'closed' AND lease_until>%s {extra} LIMIT %s
            ) bounded""",
                (tenant, now, *params, maximum),
            ).fetchone()["n"]
            >= maximum
        )
        if full:
            raise unavailable("visibility_registry_capacity")


def response(row):
    return {
        "data": wire(
            {
                key: row[key]
                for key in (
                    "id",
                    "tab_id",
                    "revision",
                    "view_epoch",
                    "query_digest",
                    "state",
                    "recorded_at",
                    "lease_until",
                    "checkpoint",
                )
            }
        ),
        "meta": {"eligibility": "unproven", "render_proof": "unavailable"},
    }


def append_control(conn, row, command_id, fingerprint):
    result = response(row)
    # Session hash is an internal binding, never included in the browser response.
    snapshot = wire({key: value for key, value in row.items() if key != "session_hash"})
    conn.execute(
        """INSERT INTO visibility_view_controls
        (tenant_id,checkpoint,view_id,session_hash,command_id,fingerprint,recorded_at,snapshot,response)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            row["tenant_id"],
            row["checkpoint"],
            row["id"],
            row["session_hash"],
            command_id,
            fingerprint,
            row["recorded_at"],
            Jsonb(snapshot),
            Jsonb(result),
        ),
    )
    return result


def snapshot_at(conn, tenant, view_id, *, checkpoint: int, at: datetime):
    """Historical reported state, NOT proof of current/historical access or eligibility.

    Both bounds matter: input order resolves same-clock controls; time preserves a
    scheduled expiry's original boundary even when the worker arrives late.
    """
    if type(checkpoint) is not int or checkpoint < 0 or at.tzinfo is None:
        raise ValueError("A nonnegative checkpoint and aware original time are required")
    row = conn.execute(
        """SELECT snapshot FROM visibility_view_controls
        WHERE tenant_id=%s AND view_id=%s AND checkpoint<=%s AND recorded_at<=%s
        ORDER BY recorded_at DESC,checkpoint DESC LIMIT 1""",
        (tenant, view_id, checkpoint, at),
    ).fetchone()
    return row["snapshot"] if row else None
