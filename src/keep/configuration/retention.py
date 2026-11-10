"""One retention predicate for history reads and bounded physical cleanup."""

from psycopg import sql
import unicodedata

from keep.configuration.models import name_key
from keep.shared.errors import unavailable

TABLES = {
    "preset": ("presets", "preset_revisions"),
    "dashboard": ("dashboards", "dashboard_revisions"),
}


def retained_versions(kind, *, all_resources=False):
    table, revisions = TABLES[kind]
    return sql.SQL("""
        SELECT r.* FROM {revisions} r
        JOIN configuration_identities i ON i.tenant_id=r.tenant_id AND i.resource_kind={kind} AND i.resource_id=r.id
        LEFT JOIN {table} p ON p.tenant_id=r.tenant_id AND p.id=r.id
        WHERE r.tenant_id=%s {resource} AND (
          (r.superseded_at IS NOT NULL AND r.superseded_at+interval '2160 hours'>%s)
          OR (r.revision=coalesce(p.revision,i.final_revision)
              AND (i.deleted_at IS NULL OR i.deleted_at+interval '2160 hours'>%s))
          OR configuration_pending_revision(r.tenant_id,{kind},r.id,r.revision)
          OR EXISTS(SELECT 1 FROM configuration_retention_holds h
              WHERE h.tenant_id=r.tenant_id AND h.resource_kind={kind} AND h.resource_id=r.id
              AND h.released_at IS NULL AND (h.revision IS NULL OR h.revision=r.revision))
          OR EXISTS(SELECT 1 FROM configuration_activity a
              WHERE a.tenant_id=r.tenant_id AND a.resource_kind={kind} AND a.resource_id=r.id
              AND r.revision IN(a.before_revision,a.after_revision)
              AND (a.recorded_at+interval '2160 hours'>%s
                OR (a.kind='deleted' AND configuration_pending_revision(a.tenant_id,a.resource_kind,a.resource_id,a.revision,true)) OR EXISTS(
                SELECT 1 FROM configuration_retention_holds h WHERE h.tenant_id=a.tenant_id
                AND h.resource_kind=a.resource_kind AND h.resource_id=a.resource_id
                AND h.released_at IS NULL AND (h.revision IS NULL OR h.revision=a.revision))))
        )
    """).format(
        table=sql.Identifier(table),
        revisions=sql.Identifier(revisions),
        kind=sql.Literal(kind),
        resource=sql.SQL("") if all_resources else sql.SQL("AND r.id=%s"),
    )


def retained_args(tenant, resource, now):
    return (tenant, resource, now, now, now)


def deleted_definitions(kind):
    """Choose the newest retained snapshot BEFORE filtering its historical name."""
    return sql.SQL("""SELECT latest.*,i.deleted_at,i.final_revision FROM (
        SELECT DISTINCT ON (id) * FROM ({retained}) retained ORDER BY id,revision DESC
      ) latest JOIN configuration_identities i ON i.tenant_id=latest.tenant_id
      AND i.resource_kind={kind} AND i.resource_id=latest.id WHERE i.deleted_at IS NOT NULL
    """).format(retained=retained_versions(kind, all_resources=True), kind=sql.Literal(kind))


def deleted_args(tenant, now):
    return (tenant, now, now, now)


def warm_history_names(conn, tenant, kind, *, limit=100):
    """Bounded derived-key backfill; authorize before calling, commit before reads.

    Persist Python's existing NFC/full-casefold profile exactly. Warm only latest
    retained deleted snapshots; expired history must not delay discoverable rows.
    No configuration revision or user activity clock changes.
    """
    if kind not in TABLES or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Known kind and bounded name warmup required")
    if unicodedata.unidata_version != "15.1.0":
        raise unavailable("configuration_name_profile_unavailable")
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    rows = conn.execute(
        sql.SQL(
            "SELECT id,revision,snapshot FROM ({}) candidates WHERE name_key IS NULL ORDER BY id LIMIT %s"
        ).format(deleted_definitions(kind)),
        (*deleted_args(tenant, now), limit),
    ).fetchall()
    for row in rows:
        value = row["snapshot"].get("name")
        if not isinstance(value, str):
            raise unavailable("configuration_history_name_unproven")
        conn.execute(
            sql.SQL(
                "UPDATE {} SET name_key=%s WHERE tenant_id=%s AND id=%s AND revision=%s AND name_key IS NULL"
            ).format(sql.Identifier(TABLES[kind][1])),
            (name_key(value), tenant, row["id"], row["revision"]),
        )
    return len(rows)
