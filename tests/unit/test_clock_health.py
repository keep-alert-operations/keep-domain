import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from appchi.clock_health import require_clock_health
from appchi.shared.errors import AppError


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
    if valid:
        require_clock_health(settings, now=now)
    else:
        with pytest.raises(AppError, match="clock_untrusted"):
            require_clock_health(settings, now=now)


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
