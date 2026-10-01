from datetime import timedelta
from uuid import UUID, uuid4

from appchi.ingestion.native import native_time
from appchi.shared.errors import AppError

SEVERITY = {"error": "critical", "major": "high", "warning": "warning", "clear": "clear"}
SEMANTIC_FIELDS = (
    "message",
    "status",
    "source_suppressed",
    "suppressed",
    "severity",
    "time_created",
    "occurrence_id",
    "occurrence_number",
    "opened_at",
    "resolved_at",
    "acknowledged",
    "acknowledged_by",
    "acknowledged_at",
    "assignee_id",
)


def apply_source(previous, item):
    source = item["payload"]
    when = item["received_at"]
    v1 = item["version"] == "v1"
    status = (
        ("resolved" if source["severity"] == "clear" else "firing")
        if v1
        else ("resolved" if source["status"] == "resolved" else "firing")
    )
    severity = SEVERITY[source["severity"]] if v1 else source["severity"]
    source_suppressed = not v1 and source["status"] == "suspended"
    if previous is None:
        current = {
            "id": uuid4(),
            "tenant_id": item["tenant_id"],
            "schema_version": item["version"],
            "key_field": item["key_field"],
            "operator": source["operator"] if v1 else str(item["operator_id"]),
            "application": source["application"],
            "component": source["object"] if v1 else source["component"],
            "node_name": source.get("node_name"),
            "site": source.get("site"),
            "impact": source.get("impact"),
            "runbook_url": source.get("runbook_url"),
            "message": source["message"],
            "severity": severity,
            "status": status,
            "source_suppressed": source_suppressed,
            "suppressed": source_suppressed,
            "time_created": native_time(source["time_created"]),
            "first_received_at": when,
            "timestamp": when,
            "occurrence_id": None,
            "occurrence_number": 0,
            "opened_at": None,
            "resolved_at": when if status == "resolved" else None,
            "acknowledged": False,
            "acknowledged_by": None,
            "acknowledged_at": None,
            "assignee_id": None,
            "revision": 1,
            "projection_version": 1,
            "history_id": item["id"],
            "last_source_activity": when,
            "retention_at": when + timedelta(days=90) if status == "resolved" else None,
        }
        if status == "firing":
            open_occurrence(current, when)
        return current, True
    current = dict(previous)
    if v1 and source["severity"] != "clear":
        if current["severity"] not in ("clear", severity):
            raise AppError("identity_conflict", "Fixed severity differs.", 409)
        current["severity"] = severity
    current["message"] = source["message"]
    current["source_suppressed"] = source_suppressed
    current["suppressed"] = (
        source_suppressed  # maintenance reducer must run before publication when enabled
    )
    if current["status"] != status:
        current["status"] = status
        if status == "firing":
            current["time_created"] = native_time(source["time_created"])
            open_occurrence(current, when)
        else:
            current["resolved_at"] = when
            current["retention_at"] = when + timedelta(days=90)
    current["timestamp"] = max(current["timestamp"], when)
    current["last_source_activity"] = max(current["last_source_activity"], when)
    current["history_id"] = item["id"]
    changed = any(current[f] != previous[f] for f in SEMANTIC_FIELDS)
    current["revision"] += int(changed)
    current["projection_version"] += 1
    return current, changed


def open_occurrence(current, when):
    current.update(
        occurrence_id=uuid4(),
        occurrence_number=current["occurrence_number"] + 1,
        opened_at=when,
        resolved_at=None,
        retention_at=None,
        acknowledged=False,
        acknowledged_by=None,
        acknowledged_at=None,
        assignee_id=None,
    )


def apply_command(current, kind, value, actor, when):
    if kind not in {"set_status", "set_assignee"}:
        raise AppError("invalid_command", "Use assignment to acknowledge an alert.", 422)
    result = dict(current)
    if kind == "set_status" and result["status"] != value:
        result["status"] = value
        if value == "firing":
            open_occurrence(result, when)
            result["last_source_activity"] = when
        else:
            result.update(resolved_at=when, retention_at=when + timedelta(days=90))
    elif kind == "set_assignee":
        result["assignee_id"] = UUID(value) if value is not None else None
    changed = any(result[f] != current[f] for f in SEMANTIC_FIELDS)
    if changed:
        result["revision"] += 1
        result["projection_version"] += 1
    return result, changed
