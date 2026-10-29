"""Read-time display-name enrichment for API responses.

Names are resolved from the directory-published ``principals`` table, managed
operators, and the tenant's own incidents while a response is being built.
They are never written into search documents, revisions, idempotent command
results or ETag inputs.
Each response performs at most one batched lookup per source (no N+1).

Principals keep their stored ``display_name`` after they become ineligible or
deleted: it is historical attribution, so it is returned rather than hidden.
Unknown identifiers yield ``None``; nothing is fabricated.
"""

from collections.abc import Iterable
from uuid import UUID
from typing import Literal
from appchi.alerts.presentation import present_alert

from pydantic import BaseModel, ConfigDict, Field

ACTOR_FIELDS = ("created_by", "updated_by")


def _uuids(values: Iterable) -> list[str]:
    result = set()
    for value in values:
        if value is None:
            continue
        try:
            result.add(str(UUID(str(value))))
        except ValueError:
            continue  # Malformed identifiers are never resolved.
    return sorted(result)


def _key(value) -> str | None:
    if value is None:
        return None
    try:
        return str(UUID(str(value)))
    except ValueError:
        return None


def principal_names(conn, ids: Iterable) -> dict[str, str]:
    """One batched lookup of stored directory display names by principal UUID."""
    keys = _uuids(ids)
    if not keys:
        return {}
    rows = conn.execute(
        "SELECT id,display_name FROM principals WHERE id=ANY(%s::uuid[])", (keys,)
    ).fetchall()
    return {str(row["id"]): row["display_name"] for row in rows}


def operator_names(conn, tenant, ids: Iterable) -> dict[str, str]:
    """Current managed operator names, restricted to the alert's tenant."""
    keys = _uuids(ids)
    if not keys:
        return {}
    rows = conn.execute(
        "SELECT id,name FROM operators WHERE tenant_id=%s AND id=ANY(%s::uuid[])",
        (str(tenant), keys),
    ).fetchall()
    return {str(row["id"]): row["name"] for row in rows}


def incident_titles(conn, tenant, ids: Iterable) -> dict[str, str]:
    """Titles of retained incidents owned by ``tenant``; other tenants never match."""
    keys = _uuids(ids)
    if not keys:
        return {}
    rows = conn.execute(
        """SELECT i.id,i.title FROM incidents i JOIN incident_identities x
        ON x.tenant_id=i.tenant_id AND x.id=i.id
        WHERE i.tenant_id=%s AND i.id=ANY(%s::uuid[]) AND x.retired_at IS NULL""",
        (str(tenant), keys),
    ).fetchall()
    return {str(row["id"]): row["title"] for row in rows}


def active_incident_ids(conn, tenant, alert_ids: Iterable) -> dict[str, str]:
    """Current active ownership (PostgreSQL authority) for alert detail reads."""
    keys = _uuids(alert_ids)
    if not keys:
        return {}
    rows = conn.execute(
        "SELECT alert_id,incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=ANY(%s::uuid[])",
        (str(tenant), keys),
    ).fetchall()
    return {str(row["alert_id"]): str(row["incident_id"]) for row in rows}


def enrich_alerts(conn, tenant, rows: list[dict]) -> list[dict]:
    """Add current ownership, operator, and active incident presentation."""
    names = principal_names(
        conn,
        [row.get("assignee_id") for row in rows],
    )
    operators = operator_names(
        conn,
        tenant,
        [row.get("operator") for row in rows if row.get("schema_version") == "v2"],
    )
    titles = incident_titles(conn, tenant, [row.get("active_incident_id") for row in rows])
    return [
        {
            **present_alert(row),
            "assignee_display_name": names.get(_key(row.get("assignee_id"))),
            "operator_display_name": (
                row.get("operator")
                if row.get("schema_version") == "v1"
                else operators.get(_key(row.get("operator")))
            ),
            "active_incident_title": titles.get(_key(row.get("active_incident_id"))),
        }
        for row in rows
    ]


def group_labels(conn, tenant, field: str, keys: Iterable) -> dict[str, str]:
    """Names for assignee and incident group values; other values are their own label."""
    if field == "assignee_id":
        return principal_names(conn, keys)
    if field == "active_incident_id":
        return incident_titles(conn, tenant, keys)
    return {}


def enrich_assignees(conn, rows: list[dict]) -> list[dict]:
    names = principal_names(conn, [row.get("assignee_id") for row in rows])
    return [
        {**row, "assignee_display_name": names.get(_key(row.get("assignee_id")))} for row in rows
    ]


def incident_origins(conn, tenant, context_ids: Iterable) -> dict[str, tuple[str, str | None]]:
    """Originating rule id and current name (null once deleted) per same-tenant context."""
    keys = _uuids(context_ids)
    if not keys:
        return {}
    rows = conn.execute(
        """SELECT c.id,c.rule_id,CASE WHEN r.deleted_at IS NULL THEN r.name END AS name
        FROM correlation_contexts c LEFT JOIN correlation_rules r
        ON r.tenant_id=c.tenant_id AND r.id=c.rule_id
        WHERE c.tenant_id=%s AND c.id=ANY(%s::uuid[])""",
        (str(tenant), keys),
    ).fetchall()
    return {str(row["id"]): (str(row["rule_id"]), row["name"]) for row in rows}


def enrich_incidents(conn, tenant, rows: list[dict]) -> list[dict]:
    """Assignee names plus the correlation origin rule for correlation-created incidents."""
    origins = incident_origins(
        conn,
        tenant,
        [row.get("context_id") for row in rows if row.get("origin") == "correlation"],
    )
    result = []
    for row in enrich_assignees(conn, rows):
        rule_id, rule_name = (
            origins.get(_key(row.get("context_id")), (None, None))
            if row.get("origin") == "correlation"
            else (None, None)
        )
        result.append({**row, "origin_rule_id": rule_id, "origin_rule_name": rule_name})
    return result


def actor_names(conn, sources: list[dict]) -> list[dict]:
    """Display names for whichever ``created_by``/``updated_by`` each source carries."""
    names = principal_names(
        conn, [source.get(field) for source in sources for field in ACTOR_FIELDS]
    )
    return [
        {
            field + "_display_name": names.get(_key(source.get(field)))
            for field in ACTOR_FIELDS
            if field in source
        }
        for source in sources
    ]


def enrich_actors(conn, rows: list[dict], sources: list[dict] | None = None) -> list[dict]:
    """Merge actor names into ``rows``; ``sources`` may supply ids a public row omits."""
    labels = actor_names(conn, rows if sources is None else sources)
    return [{**row, **label} for row, label in zip(rows, labels, strict=True)]


# OpenAPI documentation models. Routes publish them through ``responses`` so the
# generated client gains the new optional fields while the actual payload
# serialization (and every other field) stays exactly as before.
class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")


class AlertDisplayNames(_Open):
    assignee_display_name: str | None = Field(
        default=None, description="Stored directory name of assignee_id; null when unassigned."
    )
    operator_display_name: str | None = Field(
        default=None,
        description="Current same-tenant managed operator name for v2, or the exact legacy operator string for v1; null when unavailable.",
    )
    display_status: Literal["firing", "acknowledged", "resolved"] | None = Field(
        default=None,
        description="Firing with an assignee is acknowledged; resolved takes precedence. Derived from source lifecycle status and assignee_id.",
    )
    active_incident_title: str | None = Field(
        default=None,
        description="Title of the retained same-tenant active incident; null otherwise.",
    )
    dismissed_until: str | None = Field(
        default=None,
        description="End of the alert's timed dismissal (REV-49); `suppressed` already reflects it at the response's clock.",
    )


class AlertDismissal(_Open):
    until: str = Field(description="UTC end of the dismissal; it stops suppressing the alert then.")
    dismissed_at: str
    dismissed_by: str | None = None
    state: Literal["active", "expired"] = Field(
        description="Expired once the end has passed but before a write recorded that it ended."
    )


class IncidentDisplayNames(_Open):
    assignee_display_name: str | None = Field(
        default=None, description="Stored directory name of assignee_id; null when unassigned."
    )
    origin_rule_id: str | None = Field(
        default=None,
        description="Originating correlation rule of a correlation-created incident; else null.",
    )
    origin_rule_name: str | None = Field(
        default=None,
        description="Current name of the originating rule; null when deleted or unknown.",
    )


class ActorDisplayNames(_Open):
    created_by_display_name: str | None = Field(
        default=None, description="Stored directory name of the creating principal."
    )
    updated_by_display_name: str | None = Field(
        default=None, description="Stored directory name of the last updating principal."
    )


class AlertPage(_Open):
    data: list[AlertDisplayNames]
    next_cursor: str | None = None


class AlertGroupNames(_Open):
    key: str | None = Field(
        description="The group's value of the grouping field; null groups alerts without one."
    )
    label: str | None = Field(
        default=None,
        description="Directory name or incident title for assignee and incident groups; null otherwise or when unknown.",
    )
    total: str | None = Field(
        description="Exact alerts in the group as a decimal string; null when unavailable."
    )
    severity: dict[str, str] | None = Field(
        default=None, description="Exact alerts per severity in the group; null when unavailable."
    )
    status: dict[str, str] | None = Field(
        default=None,
        description="Exact alerts per visible status, for severity groups only; null otherwise.",
    )
    data: list[AlertDisplayNames]
    next_cursor: str | None = Field(
        default=None, description="Continues this group's rows through the feed's group paging."
    )


class AlertGroupPage(_Open):
    data: list[AlertGroupNames]
    next_group_cursor: str | None = None


class AlertDetailNames(AlertDisplayNames):
    active_incident_id: str | None = Field(
        default=None,
        description="Retained same-tenant active owning incident (PG ownership); null otherwise.",
    )
    dismissal: AlertDismissal | None = Field(
        default=None, description="The alert's timed dismissal (REV-49); null when none is stored."
    )


class AlertRead(_Open):
    data: AlertDetailNames


class IncidentPage(_Open):
    data: list[IncidentDisplayNames]
    next_cursor: str | None = None


class IncidentRead(_Open):
    data: IncidentDisplayNames


class ActorPage(_Open):
    data: list[ActorDisplayNames]
    next_cursor: str | None = None


class ActorRead(_Open):
    data: ActorDisplayNames


def documented(model: type[BaseModel]) -> dict:
    """``responses`` entry documenting a 200 body without changing serialization."""
    return {200: {"model": model}}
