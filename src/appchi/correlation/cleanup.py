"""Bounded correlation content retention; identities and replay fences survive.

Pending or untrusted consumer progress conservatively holds configuration. This
module never compacts journal bodies, incident provenance, or transport receipts.
"""

from dataclasses import dataclass
from datetime import timedelta
from time import monotonic
import unicodedata

from appchi.shared.errors import AppError
from appchi.shared.transactions import coordinator
from appchi.correlation.guards import _ready
from .models import NAME_PROFILE, name_key


def history_parent(conn, tenant, rule):
    row = conn.execute(
        """SELECT i.id,i.tenant_id,i.deleted_at,i.final_revision,coalesce(r.revision,i.final_revision) AS revision
        FROM correlation_rule_identities i LEFT JOIN correlation_rules r ON r.tenant_id=i.tenant_id AND r.id=i.id
        WHERE i.tenant_id=%s AND i.id=%s""",
        (tenant, rule),
    ).fetchone()
    if row is None:
        raise AppError("not_found", "Correlation rule unavailable.", 404)
    return row


# A durable cursor is necessary but not sufficient: explicit pending work and
# maintenance effects must also be settled. No wall-clock staleness heuristic.
PENDING = "correlation_rule_proof_pending(v.tenant_id,v.rule_id)"
# The same SQL predicate guards new holds so API visibility and physical
# retention cannot diverge or revive an already expired physical snapshot.
RETAINED = "correlation_revision_retained(v.tenant_id,v.rule_id,v.revision,%s)"
PARENTS = """FROM correlation_rule_revisions v JOIN correlation_rule_identities p ON p.tenant_id=v.tenant_id AND p.id=v.rule_id
 LEFT JOIN correlation_rules r ON r.tenant_id=p.tenant_id AND r.id=p.id"""


def retained_revisions(conn, row, now):
    return (
        "SELECT v.* " + PARENTS + " WHERE v.tenant_id=%s AND v.rule_id=%s AND " + RETAINED,
        [row["tenant_id"], row["id"], now],
    )


def warm_history_names(conn, tenant, *, limit=100):
    """Bounded derived-cache warmup; callers must authorize this tenant first.

    It does not change configuration, activity, or collection generation.
    Future writers populate this field atomically in the revision trigger.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Name warmup limit must be 1..100")
    if unicodedata.unidata_version != "15.1.0":
        return 0
    rows = conn.execute(
        """SELECT rule_id,revision,snapshot->>'name' AS name,snapshot->>'name_profile' AS name_profile FROM correlation_rule_revisions
        WHERE tenant_id=%s AND name_key IS NULL ORDER BY rule_id,revision LIMIT %s FOR UPDATE SKIP LOCKED""",
        (tenant, limit),
    ).fetchall()
    for row in rows:
        if not isinstance(row["name"], str) or row["name_profile"] != NAME_PROFILE:
            continue
        conn.execute(
            "UPDATE correlation_rule_revisions SET name_key=%s WHERE tenant_id=%s AND rule_id=%s AND revision=%s AND name_key IS NULL",
            (name_key(row["name"]), tenant, row["rule_id"], row["revision"]),
        )
    return len(rows)


def deleted_definitions(tenant, now):
    # Choose the latest retained revision before filtering its content, never the
    # expired final definition or an older name that merely matches a filter.
    query = (
        """SELECT snapshot,rule_id AS id,tenant_id,name_key,
      (snapshot->>'created_at')::timestamptz AS created_at,
      parent_deleted_at AS deleted_at,false AS enabled,'blocked'::text AS health,
      revision AS history_revision,final_revision FROM (
      SELECT DISTINCT ON (v.rule_id) v.*,p.deleted_at AS parent_deleted_at,p.final_revision """
        + PARENTS
        + """
      WHERE v.tenant_id=%s AND p.deleted_at IS NOT NULL AND """
        + RETAINED
        + " ORDER BY v.rule_id,v.revision DESC) latest"
    )
    return query, [tenant, now]


def cleanup_rule(db, tenant, rule, *, limit=100):
    """Return whether this resource's currently eligible work fits this turn."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup limit must be 1..100")
    with db.transaction(tenant) as conn:
        _ready(conn)
        coordinator(conn, tenant)
        conn.execute(
            "SELECT id FROM correlation_rules WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant, rule),
        )
        row = history_parent(conn, tenant, rule)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        if row["deleted_at"] is not None and row["final_revision"] != row["revision"]:
            return False
        # Match the final identity/version, not an older successful attempt.
        if (
            row["deleted_at"] is not None
            and not conn.execute(
                """SELECT 1 FROM correlation_delete_jobs WHERE tenant_id=%s AND rule_id=%s
            AND state='final_protected' AND intent_ack IS NOT NULL AND final_ack IS NOT NULL
            AND expected_revision+1=%s""",
                (tenant, rule, row["revision"]),
            ).fetchone()
        ):
            return False
        if conn.execute(
            "SELECT "
            + PENDING
            + " AS blocked FROM (SELECT %s::uuid AS tenant_id,%s::uuid AS rule_id) v",
            (tenant, rule),
        ).fetchone()["blocked"]:
            return False
        remaining = limit

        def budget(query, args):
            nonlocal remaining
            count = conn.execute(query, (*args, remaining)).rowcount
            remaining -= count
            return remaining == 0

        if row["deleted_at"] is not None and budget(
            """DELETE FROM correlation_evidence WHERE ctid IN (
            SELECT ctid FROM correlation_evidence WHERE tenant_id=%s AND rule_id=%s AND expires_at<=%s LIMIT %s)""",
            (tenant, rule, now),
        ):
            return False
        # Event expiry does not delete a held definition. Event metadata contains
        # display snapshots that must not follow the longer content lifetime.
        if budget(
            """UPDATE correlation_rule_revisions SET action=NULL,reset_reason=NULL,changed_fields=NULL,
            command_id=NULL,actor_id=NULL,actor_label=NULL WHERE (tenant_id,rule_id,revision) IN (
            SELECT tenant_id,rule_id,revision FROM correlation_rule_revisions WHERE tenant_id=%s AND rule_id=%s
            AND action IS NOT NULL AND recorded_at+interval '2160 hours'<=%s ORDER BY revision LIMIT %s)""",
            (tenant, rule, now),
        ):
            return False
        if budget(
            """DELETE FROM correlation_revision_holds WHERE ctid IN (SELECT ctid FROM correlation_revision_holds
            WHERE tenant_id=%s AND rule_id=%s AND released_at IS NOT NULL LIMIT %s)""",
            (tenant, rule),
        ):
            return False
        kept, args = retained_revisions(conn, row, now)
        if budget(
            """DELETE FROM correlation_rule_revisions WHERE (tenant_id,rule_id,revision) IN (
            SELECT tenant_id,rule_id,revision FROM correlation_rule_revisions r WHERE tenant_id=%s AND rule_id=%s
            AND NOT EXISTS(SELECT 1 FROM ("""
            + kept
            + """ ) k WHERE k.revision=r.revision)
            ORDER BY revision LIMIT %s)""",
            (tenant, rule, *args),
        ):
            return False
        # The protected ordinary-command compactor owns copied command responses.
        if budget(
            """UPDATE correlation_delete_jobs SET actor_label=NULL WHERE id IN (
            SELECT j.id FROM correlation_delete_jobs j WHERE j.tenant_id=%s AND j.rule_id=%s AND actor_label IS NOT NULL
            AND receipt IS NULL AND updated_at+interval '2160 hours'<=%s
            AND ((state='final_protected' AND final_ack IS NOT NULL) OR (state='cancelled' AND cancel_ack IS NOT NULL))
            AND NOT EXISTS(SELECT 1 FROM command_retention c WHERE c.correlation_delete_id=j.id)
            AND NOT EXISTS(SELECT 1 FROM correlation_revision_holds h WHERE h.tenant_id=j.tenant_id AND h.rule_id=j.rule_id AND h.released_at IS NULL)
            ORDER BY updated_at,id LIMIT %s)""",
            (tenant, rule, now),
        ):
            return False
        if row["deleted_at"] is None:
            return True
        if row["deleted_at"] + timedelta(days=90) > now:
            return False
        # Held old history remains accessible from the minimal parent identity,
        # even when the final current definition is independently eligible.
        if conn.execute(
            "SELECT 1 FROM (" + kept + ") k WHERE revision=%s", (*args, row["revision"])
        ).fetchone():
            return False
        if budget(
            """DELETE FROM correlation_conditions WHERE (tenant_id,rule_id,id) IN (
            SELECT tenant_id,rule_id,id FROM correlation_conditions WHERE tenant_id=%s AND rule_id=%s ORDER BY id LIMIT %s)""",
            (tenant, rule),
        ):
            return False
        if remaining:
            removed = conn.execute(
                "DELETE FROM correlation_rules WHERE tenant_id=%s AND id=%s", (tenant, rule)
            ).rowcount
            remaining -= removed
            if remaining == 0:
                return False
        # Controls/reset contexts can still be required by retained proof. Keep
        # them until every revision dependency is released. Never cascade.
        if conn.execute(
            "SELECT 1 FROM correlation_rule_revisions WHERE tenant_id=%s AND rule_id=%s LIMIT 1",
            (tenant, rule),
        ).fetchone():
            return False
        if budget(
            """DELETE FROM correlation_contexts WHERE id IN (SELECT x.id FROM correlation_contexts x
            WHERE x.tenant_id=%s AND x.rule_id=%s AND x.active_incident_id IS NULL
            AND NOT EXISTS(SELECT 1 FROM incidents i WHERE i.tenant_id=x.tenant_id AND i.context_id=x.id)
            AND NOT EXISTS(SELECT 1 FROM correlation_decisions d WHERE d.tenant_id=x.tenant_id AND d.context_id=x.id)
            AND NOT EXISTS(SELECT 1 FROM correlation_evidence e WHERE e.tenant_id=x.tenant_id AND e.context_id=x.id)
            ORDER BY x.id LIMIT %s)""",
            (tenant, rule),
        ):
            return False
        if conn.execute(
            "SELECT 1 FROM correlation_contexts WHERE tenant_id=%s AND rule_id=%s LIMIT 1",
            (tenant, rule),
        ).fetchone():
            return False
        if budget(
            """DELETE FROM correlation_rule_controls WHERE id IN (SELECT id FROM correlation_rule_controls
            WHERE tenant_id=%s AND rule_id=%s ORDER BY tenant_order LIMIT %s)""",
            (tenant, rule),
        ):
            return False
        return True


@dataclass(frozen=True)
class CleanupTurn:
    attempted: int
    completed: int
    cursor: tuple | None


def correlation_cleanup_turn(db, *, cursor=None, limit=20):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup scan limit must be 1..100")
    with db.transaction() as conn:
        _ready(conn)
        query = """SELECT tenant_id,id FROM correlation_rule_identities i WHERE (
         EXISTS(SELECT 1 FROM correlation_rules r WHERE r.tenant_id=i.tenant_id AND r.id=i.id)
         OR EXISTS(SELECT 1 FROM correlation_rule_revisions r WHERE r.tenant_id=i.tenant_id AND r.rule_id=i.id)
         OR EXISTS(SELECT 1 FROM correlation_contexts x WHERE x.tenant_id=i.tenant_id AND x.rule_id=i.id)
         OR EXISTS(SELECT 1 FROM correlation_rule_controls c WHERE c.tenant_id=i.tenant_id AND c.rule_id=i.id)
         OR EXISTS(SELECT 1 FROM correlation_delete_jobs j WHERE j.tenant_id=i.tenant_id AND j.rule_id=i.id AND j.actor_label IS NOT NULL))"""
        args = []
        if cursor is not None:
            query += " AND (tenant_id,id)>(%s,%s)"
            args.extend(cursor)
        rows = conn.execute(
            query + " ORDER BY tenant_id,id LIMIT %s", (*args, limit + 1)
        ).fetchall()
    attempted = completed = 0
    position = None
    started = monotonic()
    for row in rows[:limit]:
        completed += cleanup_rule(db, row["tenant_id"], row["id"])
        attempted += 1
        position = (row["tenant_id"], row["id"])
        if monotonic() - started >= 0.1:
            break
    return CleanupTurn(attempted, completed, position if attempted < len(rows) else None)
