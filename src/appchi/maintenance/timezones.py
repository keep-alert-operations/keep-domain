"""Pinned tzdata conversion; the host/browser timezone database is never authority."""

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import files
import re
from typing import Literal
from zoneinfo import ZoneInfo

import tzdata

PINNED_TZDATA_VERSION = "2025.2"


class ScheduleError(ValueError):
    def __init__(self, code: str, message: str, *, candidates=()):
        super().__init__(message)
        self.code, self.candidates = code, candidates


@dataclass(frozen=True)
class ConvertedEndpoint:
    timezone: str
    local: str
    utc: datetime
    offset_seconds: int
    occurrence: Literal["first", "second"] | None
    tzdata_version: str = PINNED_TZDATA_VERSION


@lru_cache(maxsize=1)
def supported_zones() -> tuple[str, ...]:
    if tzdata.__version__ != PINNED_TZDATA_VERSION:
        raise ScheduleError(
            "timezone_data_unqualified",
            "The installed timezone data does not match the pinned release.",
        )
    return tuple(sorted(set(files("tzdata").joinpath("zones").read_text().splitlines()) | {"UTC"}))


@lru_cache(maxsize=128)
def zone(identifier: str) -> ZoneInfo:
    if identifier not in supported_zones():
        raise ScheduleError(
            "invalid_timezone", "Use a recognized case-sensitive IANA timezone identifier."
        )
    # from_file ensures even Linux deployments with OS tzdata use our lockfile.
    with files("tzdata.zoneinfo").joinpath(*identifier.split("/")).open("rb") as stream:
        return ZoneInfo.from_file(stream, key=identifier)


def local_to_utc(
    identifier: str, local: str, occurrence: Literal["first", "second"] | None = None
) -> ConvertedEndpoint:
    if not isinstance(local, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", local
    ):
        raise ScheduleError("invalid_local_time", "Use YYYY-MM-DDTHH:mm:ss without an offset.")
    try:
        naive = datetime.fromisoformat(local)
    except ValueError:
        raise ScheduleError("invalid_local_time", "The local calendar time is invalid.") from None
    selected = zone(identifier)
    candidates = {}
    for fold in (0, 1):
        try:
            candidate = naive.replace(tzinfo=selected, fold=fold)
            utc = candidate.astimezone(UTC)
            back = utc.astimezone(selected)
            if back.replace(tzinfo=None) == naive:
                candidates[utc] = int(candidate.utcoffset().total_seconds())
        except (OverflowError, ValueError):
            continue
    ordered = sorted(candidates.items())
    if not ordered:
        raise ScheduleError(
            "nonexistent_local_time",
            "The local time does not exist or converts outside years 0001–9999.",
        )
    if len(ordered) == 2 and occurrence not in ("first", "second"):
        raise ScheduleError(
            "ambiguous_local_time",
            "Choose the first or second occurrence.",
            candidates=tuple(
                {"utc": at.isoformat(), "offset_seconds": offset} for at, offset in ordered
            ),
        )
    if len(ordered) == 1 and occurrence is not None:
        raise ScheduleError(
            "unexpected_occurrence", "An occurrence is allowed only for an ambiguous local time."
        )
    index = 1 if occurrence == "second" else 0
    return ConvertedEndpoint(identifier, local, ordered[index][0], ordered[index][1], occurrence)


def validate_schedule(
    start: ConvertedEndpoint, end: ConvertedEndpoint, action_time: datetime
) -> None:
    if action_time.tzinfo is None or action_time.utcoffset() is None:
        raise ScheduleError(
            "authoritative_time_required", "An aware database action time is required."
        )
    if start.timezone != end.timezone:
        raise ScheduleError(
            "timezone_mismatch", "Both endpoints use the selected schedule timezone."
        )
    if end.utc <= start.utc or end.utc <= action_time:
        raise ScheduleError(
            "invalid_end", "End must be after start and the authoritative action time."
        )


def render_endpoint(original: ConvertedEndpoint, identifier: str | None = None) -> dict:
    selected = identifier or original.timezone
    current = original.utc.astimezone(zone(selected))
    local = current.replace(tzinfo=None).isoformat(timespec="seconds")
    offset = int(current.utcoffset().total_seconds())
    return {
        "utc": original.utc.isoformat(),
        "timezone": selected,
        "local": local,
        "offset_seconds": offset,
        "tzdata_version": PINNED_TZDATA_VERSION,
        "original_local": original.local,
        "original_timezone": original.timezone,
        "original_offset_seconds": original.offset_seconds,
        "original_tzdata_version": original.tzdata_version,
        "rules_changed": selected == original.timezone
        and (local != original.local or offset != original.offset_seconds),
    }
