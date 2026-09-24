"""Searchable catalog; source ingestion schemas do not expand this vocabulary."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    kind: str
    nullable: bool = False
    max_bytes: int = 1024
    values: tuple[str, ...] = ()


FIELDS = {
    name: Field("string")
    for name in (
        "id",
        "tenant_id",
        "key_field",
        "operator",
        "application",
        "component",
    )
}
FIELDS.update(
    {
        name: Field("string", True)
        for name in (
            "node_name",
            "site",
            "occurrence_id",
            "acknowledged_by",
            "assignee_id",
            "active_incident_id",
        )
    }
)
FIELDS.update(
    {
        "key_field": Field("string", max_bytes=4096),
        "message": Field("string", max_bytes=32768),
        "impact": Field("string", True, 16384),
        "runbook_url": Field("string", True, 8192),
        "schema_version": Field("enum", values=("v1", "v2")),
        "severity": Field("enum", values=("critical", "high", "warning", "clear")),
        "status": Field("enum", values=("firing", "resolved")),
        "acknowledged": Field("bool"),
        "suppressed": Field("bool"),
        "occurrence_number": Field("int"),
        "incident_ids": Field("ids"),
    }
)
FIELDS.update(
    {
        name: Field("time", name in {"opened_at", "resolved_at", "acknowledged_at"})
        for name in (
            "time_created",
            "first_received_at",
            "timestamp",
            "last_received_at",
            "opened_at",
            "resolved_at",
            "acknowledged_at",
        )
    }
)
RULE_FIELDS = frozenset(
    (
        "id",
        "tenant_id",
        "schema_version",
        "key_field",
        "operator",
        "application",
        "component",
        "node_name",
        "site",
        "impact",
        "runbook_url",
        "message",
        "severity",
        "status",
        "time_created",
        "acknowledged",
        "acknowledged_by",
        "assignee_id",
    )
)


def storage_name(name: str) -> str:
    return "last_received_at" if name == "timestamp" else name
