"""Protected whole-timeline cleanup for explicitly deleted maintenance windows."""

from dataclasses import dataclass
from datetime import timedelta
from time import monotonic

from psycopg import sql

from keep.maintenance.retention import dependency_held
from keep.recovery.incidents import ready
from keep.shared.transactions import coordinator


def _scrub_jobs(conn, tenant, window, limit):
    return conn.execute(
        """UPDATE maintenance_delete_jobs SET actor_label=NULL WHERE id IN (
          SELECT j.id FROM maintenance_delete_jobs j WHERE j.tenant_id=%s AND j.window_id=%s
          AND j.actor_label IS NOT NULL AND j.receipt IS NULL AND j.updated_at+interval '2160 hours'<=clock_timestamp()
          AND ((j.state='final_protected' AND j.final_ack IS NOT NULL) OR (j.state='cancelled' AND j.cancel_ack IS NOT NULL))
          AND NOT EXISTS(SELECT 1 FROM command_retention c WHERE c.maintenance_delete_id=j.id)
          ORDER BY j.updated_at,j.id LIMIT %s)""",
        (tenant, window, limit),
    ).rowcount


def cleanup_window(db, tenant, window, *, limit=100):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup limit must be 1..100")
    with db.transaction(tenant) as conn:
        ready(conn)
        _, now = coordinator(conn, tenant)
        row = conn.execute(
            "SELECT * FROM maintenance_windows WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant, window),
        ).fetchone()
        if dependency_held(conn, tenant, window):
            return False
        removed = _scrub_jobs(conn, tenant, window, limit)
        if not row:
            return removed < limit
        if row["deleted_at"] is None:
            return True
        if row["deleted_at"] + timedelta(days=90) > now:
            return False
        proof = conn.execute(
            """SELECT 1 FROM maintenance_delete_jobs j JOIN maintenance_identities i ON i.tenant_id=j.tenant_id AND i.id=j.window_id
            WHERE j.tenant_id=%s AND j.window_id=%s AND j.state='final_protected' AND j.final_ack IS NOT NULL
            AND j.expected_revision+1=%s AND i.final_revision=%s AND i.deleted_at=%s""",
            (tenant, window, row["revision"], row["revision"], row["deleted_at"]),
        ).fetchone()
        if not proof:
            return False
        began = conn.execute(
            "INSERT INTO maintenance_content_retirements(tenant_id,window_id,final_revision,state) VALUES(%s,%s,%s,'erasing') ON CONFLICT DO NOTHING RETURNING window_id",
            (tenant, window, row["revision"]),
        ).fetchone()
        if began:
            conn.execute(
                "UPDATE tenant_view_state SET maintenance_generation=maintenance_generation+1,resource_generation=resource_generation+1,view_generation=view_generation+1 WHERE tenant_id=%s",
                (tenant,),
            )
        remaining = limit - removed
        started = monotonic()
        for table in (
            "maintenance_fanout_jobs",
            "maintenance_segments",
            "maintenance_controls",
            "maintenance_revisions",
        ):
            if remaining == 0 or monotonic() - started >= 0.1:
                return False
            removed = conn.execute(
                sql.SQL(
                    "DELETE FROM {} WHERE (tableoid,ctid) IN (SELECT tableoid,ctid FROM {} WHERE tenant_id=%s AND window_id=%s LIMIT %s)"
                ).format(sql.Identifier(table), sql.Identifier(table)),
                (tenant, window, remaining),
            ).rowcount
            remaining -= removed
        if remaining == 0:
            return False
        conn.execute(
            "DELETE FROM maintenance_windows WHERE tenant_id=%s AND id=%s", (tenant, window)
        )
        conn.execute(
            "UPDATE maintenance_content_retirements SET state='cleaned',completed_at=clock_timestamp() WHERE tenant_id=%s AND window_id=%s",
            (tenant, window),
        )
        return True


@dataclass(frozen=True)
class CleanupTurn:
    attempted: int
    completed: int
    cursor: tuple | None


def cleanup_turn(db, *, cursor=None, limit=20):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup scan limit must be 1..100")
    with db.transaction() as conn:
        ready(conn)
        query = "SELECT * FROM (SELECT tenant_id,id FROM maintenance_windows WHERE deleted_at+interval '2160 hours'<=clock_timestamp() UNION SELECT tenant_id,window_id FROM maintenance_delete_jobs WHERE actor_label IS NOT NULL AND state IN ('final_protected','cancelled')) candidates"
        args = []
        if cursor:
            query += " WHERE (tenant_id,id)>(%s,%s)"
            args.extend(cursor)
        rows = conn.execute(
            query + " ORDER BY tenant_id,id LIMIT %s", (*args, limit + 1)
        ).fetchall()
    attempted = completed = 0
    position = None
    started = monotonic()
    for row in rows[:limit]:
        completed += cleanup_window(db, row["tenant_id"], row["id"])
        attempted += 1
        position = (row["tenant_id"], row["id"])
        if monotonic() - started >= 0.1:
            break
    return CleanupTurn(attempted, completed, position if attempted < len(rows) else None)
