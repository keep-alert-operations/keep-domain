"""Timed dismissal: a separate suppression cause stored on the alert row (REV-49).

The stored ``suppressed`` flag keeps the source and maintenance causes. Readers
compare ``dismissed_until`` with their own clock, so a dismissal stops hiding an
alert at its end without a scheduler. Correlation instead treats a recorded
dismissal as suppression until a source input or command clears it, as it does
for stored maintenance causes.
"""

from collections.abc import Mapping
from datetime import datetime, timedelta

from appchi.shared.errors import AppError

MAX_DISMISSAL = timedelta(days=30)
DISMISSAL_FIELDS = ("dismissed_until", "dismissed_at", "dismissed_by")


def _instant(value):
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def dismissal_recorded(row) -> bool:
    """A dismissal is stored and has not yet been cleared by a write."""
    return row is not None and row.get("dismissed_until") is not None


def dismissal_active(row, at: datetime) -> bool:
    """Coverage is start-inclusive and end-exclusive against ``at``."""
    until = _instant(row.get("dismissed_until")) if row is not None else None
    return until is not None and at < until


def effective_suppressed(row, at: datetime) -> bool:
    return bool(row["suppressed"]) or dismissal_active(row, at)


def correlation_suppressed(row) -> bool:
    return bool(row["suppressed"]) or dismissal_recorded(row)


def dismissal_view(row, at: datetime):
    """Read model for detail and command responses; null when none is stored."""
    if not dismissal_recorded(row):
        return None
    return {
        "until": row["dismissed_until"],
        "dismissed_at": row["dismissed_at"],
        "dismissed_by": row.get("dismissed_by"),
        "state": "active" if dismissal_active(row, at) else "expired",
    }


def clear_dismissal(row):
    row.update(dismissed_until=None, dismissed_at=None, dismissed_by=None)


def expire_dismissal(row, at: datetime) -> bool:
    """Clear a dismissal whose end is at or before ``at``; True when it ended."""
    if dismissal_recorded(row) and not dismissal_active(row, at):
        clear_dismissal(row)
        return True
    return False


def dismissal_value(value):
    """Normalise a command value; contracts already enforce its shape."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        value = value.model_dump()
    return value


def apply_dismissal(result, value, actor, when):
    """Apply ``set_dismissal`` to a command result row in place."""
    value = dismissal_value(value)
    if value is None:
        if dismissal_recorded(result):
            clear_dismissal(result)
        return
    if result["status"] != "firing":
        raise AppError("alert_not_firing", "Only a firing alert can be dismissed.", 422)
    if value.get("duration_seconds") is not None:
        until = when + timedelta(seconds=value["duration_seconds"])
    else:
        until = _instant(value["until"])
    if until <= when:
        raise AppError("dismissal_end_passed", "Choose a time after now.", 422)
    if until - when > MAX_DISMISSAL:
        raise AppError("dismissal_too_long", "A dismissal can last up to 30 days.", 422)
    if _instant(result.get("dismissed_until")) == until:
        return
    result.update(dismissed_until=until, dismissed_at=when, dismissed_by=actor)


def dismissal_reason(value):
    value = dismissal_value(value)
    reason = value.get("reason") if value else None
    return reason.strip() if isinstance(reason, str) and reason.strip() else None
