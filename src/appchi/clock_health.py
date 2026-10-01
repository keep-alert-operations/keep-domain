"""Owner-published host clock evidence; UTC is not a distributed total order."""

from datetime import UTC, datetime
import json
import math

from appchi.shared.errors import unavailable


def require_clock_health(settings, *, now=None):
    path = getattr(settings, "clock_health_file", None)
    if path is None and settings.environment == "development":
        return  # explicit unqualified local mode
    _require_evidence(path, now=now)
    role = getattr(settings, "role", None)
    if role is not None and role not in ("ingestion-api", "private-ingestion"):
        _require_evidence(getattr(settings, "database_clock_health_file", None), now=now)


def _require_evidence(path, *, now=None):
    try:
        raw = path.read_bytes()
        if len(raw) > 4096:
            raise ValueError()
        evidence = json.loads(raw)
        measured = datetime.fromisoformat(evidence["measured_at"].replace("Z", "+00:00"))
        offset = evidence["offset_seconds"]
        age = ((now or datetime.now(UTC)) - measured).total_seconds()
        if (
            evidence["synchronized"] is not True
            or type(offset) not in (int, float)
            or not math.isfinite(offset)
            or abs(offset) > 1
            or not -1 <= age <= 60
        ):
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise unavailable("clock_untrusted") from None
