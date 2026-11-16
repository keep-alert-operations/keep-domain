"""The one registry of log fields: short name, record path and type (REV-74).

Keep does not configure the logs Elasticsearch, so its automatic mapping takes each
field's type from the first value it sees. Declaring every field once here, with one
type, is what keeps that mapping stable across services. A record may carry only
these fields; see observability 2.
"""

from typing import NamedTuple


class Field(NamedTuple):
    path: str
    kind: str  # keyword | text | long | double | boolean


def _fields(kind, **paths):
    return {name: Field(path, kind) for name, path in paths.items()}


def _keep(kind, *names):
    return {name: Field(f"keep.{name}", kind) for name in names}


FIELDS = {
    **_fields(
        "keyword",
        request_id="http.request.id",
        method="http.request.method",
        principal_id="user.id",
        error_code="error.code",
        error_class="error.type",
        topic="keep.kafka.topic",
        consumer="keep.kafka.consumer",
        # The alert's lookup keys, for records that name an alert without loading it.
        alert_id="keep.alert.id",
        alert_key_digest="keep.alert.key_digest",
    ),
    **_keep(
        "keyword",
        "role",
        "route",
        "sli",
        "tenant_id",
        "incident_id",
        "operator_id",
        # The user an alert is assigned to, as a principal UUID like user.id.
        "assignee_id",
        "rule_id",
        "window_id",
        "preset_id",
        "dashboard_id",
        "delivery_id",
        "changed_event_id",
        "command_id",
        "operation_id",
        "outcome",
        "reason",
        "cause",
        "status_before",
        "status_after",
        "sqlstate",
        "dependency",
        "operation",
        "resource",
        "action",
        "origin",
        "mode",
        "stage",
        "state",
        "kind",
        "api",
        "version",
        # The section of the UI a browser event came from.
        "view",
        # Names of the fields a rejected alert got wrong; a list of keywords.
        "fields",
    ),
    **_fields("text", stack="error.stack_trace"),
    **_fields(
        "long",
        status="http.response.status_code",
        body_bytes="http.request.body.bytes",
        partition="keep.kafka.partition",
        offset="keep.kafka.offset",
        # The order of a step within one alert's pass through a service (flow.py).
        sequence="event.sequence",
    ),
    **_keep("long", "projection_seq", "count", "attempt", "repeats", "member", "revision"),
    **_keep("double", "lead_seconds", "delay_seconds"),
    **_keep("boolean", "audit", "suppressed", "time_defaulted"),
}

# Seconds in, nanoseconds out: the Elastic Common Schema unit for event.duration.
DURATION = "duration"

# The alert's own native names (alert operations). ``id`` and ``key_digest`` are
# Keep's lookup keys; the rest are what a sender submitted. Nothing a sender names
# ever becomes a field: unknown keys are dropped by keep.observability.alerts.
ALERT_IDENTIFYING = (
    "application",
    "component",
    "object",
    "node_name",
    "name",
    "site",
    "severity",
    "status",
)
ALERT_CONTENT = ("message", "impact", "runbook_url", "operator", "time_created", "key_field")
ALERT_KEYS = ("id", "key_digest", "native_version", "provider")
ALERT_FIELDS = {
    name: Field(f"keep.alert.{name}", "text" if name in ("message", "impact") else "keyword")
    for name in (*ALERT_KEYS, *ALERT_IDENTIFYING, *ALERT_CONTENT)
}


def coerce(kind, value):
    """One Python type per field kind, so a field never changes type between records."""
    if kind == "long":
        return int(value)
    if kind == "double":
        return float(value)
    if kind == "boolean":
        return bool(value)
    if isinstance(value, (list, tuple)):
        # A keyword field may hold several values; bound both count and length.
        return [str(item)[:128] for item in value[:32]]
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
