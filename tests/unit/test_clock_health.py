import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from keep import clock_health
from keep.clock_health import ClockEvidenceCache, require_clock_health
from keep.shared.errors import AppError


@pytest.mark.parametrize(
    "offset,age,synchronized,valid",
    [
        (0, 0, True, True),
        (1, 60, True, True),
        (1.001, 0, True, False),
        (0, 61, True, False),
        (0, -2, True, False),
        (0, 0, False, False),
    ],
)
def test_clock_evidence_thresholds(tmp_path, offset, age, synchronized, valid):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(
        json.dumps(
            {
                "offset_seconds": offset,
                "measured_at": (now - timedelta(seconds=age)).isoformat(),
                "synchronized": synchronized,
            }
        )
    )
    settings = SimpleNamespace(environment="production", clock_health_file=path)
    for cache in (None, ClockEvidenceCache()):
        if valid:
            require_clock_health(settings, now=now, cache=cache)
        else:
            with pytest.raises(AppError, match="clock_untrusted"):
                require_clock_health(settings, now=now, cache=cache)


def test_authority_workload_requires_database_clock_but_ingress_does_not(tmp_path):
    now = datetime.now(UTC)
    path = tmp_path / "host-clock.json"
    path.write_text(
        json.dumps({"offset_seconds": 0, "measured_at": now.isoformat(), "synchronized": True}),
        encoding="utf8",
    )
    settings = SimpleNamespace(environment="production", role="source", clock_health_file=path)
    with pytest.raises(AppError, match="clock_untrusted"):
        require_clock_health(settings, now=now)
    settings.role = "ingestion-api"
    require_clock_health(settings, now=now)
    settings.role = "source"
    settings.database_clock_health_file = path
    require_clock_health(settings, now=now)


class Ticks:
    """Controllable monotonic time for the evidence cache."""

    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


def evidence(measured_at, *, synchronized=True, offset=0):
    return json.dumps(
        {
            "offset_seconds": offset,
            "measured_at": measured_at.isoformat(),
            "synchronized": synchronized,
        }
    )


@pytest.fixture
def reads(monkeypatch):
    """Records each evidence file the cache opens."""
    opened = []

    def counting_open(path, *args, **kwargs):
        opened.append(path)
        return open(path, *args, **kwargs)

    monkeypatch.setattr(clock_health, "open", counting_open, raising=False)
    return opened


def cached(**kwargs):
    ticks = Ticks()
    return ClockEvidenceCache(clock=ticks, **kwargs), ticks


def test_cache_reads_unchanged_evidence_once_per_interval(tmp_path, reads):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now))
    cache, ticks = cached()
    for _ in range(50):
        cache.require(path, now=now)
    assert len(reads) == 1
    ticks.value += 0.999
    cache.require(path, now=now)
    assert len(reads) == 1
    ticks.value += 0.001
    cache.require(path, now=now)
    assert len(reads) == 2
    # A monotonic value behind the parse (never expected) also forces a read.
    ticks.value -= 5
    cache.require(path, now=now)
    assert len(reads) == 3


def test_cache_rereads_at_once_when_modification_time_changes(tmp_path, reads):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now))
    cache, _ = cached()
    cache.require(path, now=now)
    # Same length and file; only the content and modification time move.
    path.write_text(evidence(now, offset=9))
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(path, now=now)
    assert len(reads) == 2


def test_cache_sees_atomic_replacement_with_identical_size_and_mtime(tmp_path, reads):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now))
    original = path.stat()
    cache, _ = cached()
    cache.require(path, now=now)
    # The publisher renames a same-length unhealthy file in within one timestamp tick.
    replacement = tmp_path / "clock.json.tmp"
    replacement.write_text(evidence(now).replace("true", "null"))
    assert replacement.stat().st_size == original.st_size
    os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
    os.replace(replacement, path)
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(path, now=now)
    assert len(reads) == 2


def test_cache_bounds_an_undetectable_in_place_rewrite_to_the_interval(
    tmp_path, reads, monkeypatch
):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now))
    real = os.stat(path)
    cache, ticks = cached()
    cache.require(path, now=now)
    # A coarse timestamp (ext4 jiffies, FAT, lazy NTFS update) can leave every
    # identity field unchanged after an in-place rewrite of the same length.
    path.write_text(evidence(now).replace("true", "null"))
    monkeypatch.setattr(clock_health, "_stat", lambda key: real)
    cache.require(path, now=now)  # tolerated only within the interval
    assert len(reads) == 1
    ticks.value += 1
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(path, now=now)
    assert len(reads) == 2


def test_cached_evidence_still_expires_with_its_own_validity(tmp_path, reads):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now))
    cache, _ = cached(recheck_seconds=3600)
    cache.require(path, now=now)
    cache.require(path, now=now + timedelta(seconds=60))
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(path, now=now + timedelta(seconds=60, microseconds=1))
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(path, now=now - timedelta(seconds=1, microseconds=1))
    # Expiry is judged from the cached value; no file read was needed.
    assert len(reads) == 1


def test_cached_evidence_expires_with_the_real_clock(tmp_path, reads, monkeypatch):
    measured = datetime(2026, 10, 7, tzinfo=UTC)
    current = [measured]

    class WallClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return current[0]

    monkeypatch.setattr(clock_health, "datetime", WallClock)
    path = tmp_path / "clock.json"
    path.write_text(evidence(measured))
    cache, _ = cached(recheck_seconds=3600)
    cache.require(path)
    current[0] = measured + timedelta(seconds=61)
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(path)
    assert len(reads) == 1


@pytest.mark.parametrize(
    "content",
    [
        lambda now: evidence(now, synchronized=False),
        lambda now: evidence(now, offset=1.5),
        lambda now: evidence(now, offset=float("nan")),
        lambda now: evidence(now).replace('"synchronized": true', '"synchronized": 1'),
        lambda now: evidence(now.replace(tzinfo=None)),
        lambda now: "{",
        lambda now: " " * 5000,
    ],
)
def test_cache_never_accepts_unhealthy_evidence(tmp_path, reads, content):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(content(now))
    cache, _ = cached()
    for _ in range(3):
        with pytest.raises(AppError, match="clock_untrusted"):
            cache.require(path, now=now)


def test_unhealthy_evidence_is_not_cached_and_recovery_is_seen(tmp_path, reads):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now, synchronized=False))
    cache, _ = cached()
    for _ in range(3):
        with pytest.raises(AppError, match="clock_untrusted"):
            cache.require(path, now=now)
    assert len(reads) == 3
    path.write_text(evidence(now) + " ")
    cache.require(path, now=now)


def test_missing_evidence_fails_closed_despite_a_cached_entry(tmp_path, reads):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now))
    cache, _ = cached()
    cache.require(path, now=now)
    path.unlink()
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(path, now=now)
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(None, now=now)
    with pytest.raises(AppError, match="clock_untrusted"):
        cache.require(tmp_path / "never-published.json", now=now)
    path.write_text(evidence(now))
    cache.require(path, now=now)


def test_require_clock_health_with_cache_checks_both_files(tmp_path, reads):
    now = datetime.now(UTC)
    host, database = tmp_path / "host.json", tmp_path / "pg.json"
    host.write_text(evidence(now))
    database.write_text(evidence(now))
    settings = SimpleNamespace(
        environment="production",
        role="source",
        clock_health_file=host,
        database_clock_health_file=database,
    )
    cache = ClockEvidenceCache()
    for _ in range(20):
        require_clock_health(settings, now=now, cache=cache)
    assert sorted(reads) == sorted([os.fspath(host), os.fspath(database)])
    database.unlink()
    with pytest.raises(AppError, match="clock_untrusted"):
        require_clock_health(settings, now=now, cache=cache)
    settings.role = "ingestion-api"
    require_clock_health(settings, now=now, cache=cache)
    settings.clock_health_file = None
    with pytest.raises(AppError, match="clock_untrusted"):
        require_clock_health(settings, now=now, cache=cache)
    development = SimpleNamespace(environment="development", clock_health_file=None)
    require_clock_health(development, cache=cache)


def test_cache_is_safe_across_threads(tmp_path, reads):
    now = datetime.now(UTC)
    path = tmp_path / "clock.json"
    path.write_text(evidence(now))
    cache = ClockEvidenceCache(recheck_seconds=3600)
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda _: cache.require(path, now=now), range(400)))
    # Concurrent first misses may each read; afterwards the entry is shared.
    assert 1 <= len(reads) <= 8
