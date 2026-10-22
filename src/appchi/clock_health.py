"""Owner-published host clock evidence; UTC is not a distributed total order."""

from datetime import UTC, datetime
import json
import math
from os import fspath, stat as _stat
from threading import Lock
from time import monotonic

from appchi.shared.errors import unavailable

MAX_EVIDENCE_BYTES = 4096


def require_clock_health(settings, *, now=None, cache=None):
    """Fail closed unless current host (and, for authority roles, database) evidence is healthy.

    Without ``cache`` every call reads the files. A long-lived caller passes one
    ``ClockEvidenceCache`` to skip unchanged re-reads; freshness is still judged on
    every call.
    """
    path = getattr(settings, "clock_health_file", None)
    if path is None and settings.environment == "development":
        return  # explicit unqualified local mode
    check = _require_evidence if cache is None else cache.require
    check(path, now=now)
    role = getattr(settings, "role", None)
    if role is not None and role not in ("ingestion-api", "private-ingestion"):
        check(getattr(settings, "database_clock_health_file", None), now=now)


class ClockEvidenceCache:
    """Thread-safe reuse of parsed clock evidence between file changes.

    Each call stats the file. Parsed evidence is reused only while the file's
    identity (device, inode/file ID, size, modification and change times) is
    unchanged *and* the parse is younger than ``recheck_seconds`` of monotonic
    time. Atomic replacement (rename, Kubernetes ConfigMap symlink swap) changes
    the identity and is seen at once. An in-place rewrite that a coarse
    timestamp (ext4 jiffies, FAT, lazily updated NTFS times) leaves with an
    identical identity is seen within ``recheck_seconds``.

    Offset, ``synchronized`` and the size limit are validated before any
    evidence is reused, and age is evaluated on every call from the cached
    ``measured_at``, so cached evidence is never accepted beyond its own 60
    second validity. Missing, unreadable, oversized, malformed, unsynchronized or
    out-of-bound-offset evidence is never cached and fails closed on that call.
    Stale, future-dated or naive-timestamp evidence may be cached and is
    rejected on every call; its replacement is seen like any other change, at
    once when the identity changes and otherwise within ``recheck_seconds``.
    """

    def __init__(self, *, recheck_seconds=1.0, clock=monotonic):
        self.recheck_seconds = recheck_seconds
        self._clock = clock
        self._lock = Lock()
        self._entries = {}

    def require(self, path, *, now=None):
        """Raise ``clock_untrusted`` unless the evidence at ``path`` is healthy at ``now``."""
        try:
            key = fspath(path)
            stat = _stat(key)
            identity = (
                stat.st_dev,
                stat.st_ino,
                stat.st_size,
                stat.st_mtime_ns,
                stat.st_ctime_ns,
            )
            checked = self._clock()
            with self._lock:
                entry = self._entries.get(key)
            if (
                entry is None
                or entry[0] != identity
                or not 0 <= checked - entry[1] < self.recheck_seconds
            ):
                with self._lock:
                    self._entries.pop(key, None)
                if stat.st_size > MAX_EVIDENCE_BYTES:
                    raise ValueError()
                # Stat precedes the read: a replacement in between is stored under
                # the older identity and therefore re-read on the next call.
                with open(key, "rb") as handle:
                    evidence = _parse(handle.read(MAX_EVIDENCE_BYTES + 1))
                with self._lock:
                    self._entries[key] = (identity, checked, evidence)
            else:
                evidence = entry[2]
            _require_current(evidence, now)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            raise unavailable("clock_untrusted") from None


def _require_evidence(path, *, now=None):
    try:
        _require_current(_parse(path.read_bytes()), now)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise unavailable("clock_untrusted") from None


def _parse(raw):
    """Validate the time-independent fields; returns (measured_at, offset)."""
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError()
    evidence = json.loads(raw)
    measured = datetime.fromisoformat(evidence["measured_at"].replace("Z", "+00:00"))
    offset = evidence["offset_seconds"]
    if (
        evidence["synchronized"] is not True
        or type(offset) not in (int, float)
        or not math.isfinite(offset)
        or abs(offset) > 1
    ):
        raise ValueError()
    return measured, offset


def _require_current(evidence, now):
    measured, _ = evidence
    age = ((now or datetime.now(UTC)) - measured).total_seconds()
    if not -1 <= age <= 60:
        raise ValueError()
