from datetime import UTC, datetime

from pydantic import ValidationError
import pytest

from appchi.configuration.models import GROUPABLE, PresetDefinition
from appchi.search import reader
from appchi.shared.errors import AppError

BASE = {
    "name": "Payments",
    "cel": "true",
    "sort": [{"field": "timestamp", "direction": "desc"}],
    "columns": ["severity", "message"],
}


def test_group_by_is_optional_and_whitelisted():
    """Requirements: REV-44; preset operations 3 and 4."""
    assert PresetDefinition(**BASE).group_by is None
    assert PresetDefinition(**BASE, group_by="application").group_by == "application"
    for value in ("message", "timestamp", "operator", "status", ""):
        with pytest.raises(ValidationError):
            PresetDefinition(**BASE, group_by=value)


def test_definition_and_execution_vocabularies_match():
    """Requirements: REV-44; preset operations 4."""
    assert GROUPABLE == set(reader.GROUPABLE)


def test_group_order_and_filters():
    """Requirements: REV-44; preset operations 4; technical baseline 17."""
    bucket = reader._Bucket
    ordered = reader.order_groups(
        "application",
        [bucket("b", 2, {}, None), bucket(None, 9, {}, None), bucket("a", 2, {}, None)],
    )
    assert [item.key for item in ordered] == ["a", "b", None]
    ordered = reader.order_groups(
        "severity", [bucket("clear", 9, {}, None), bucket("critical", 1, {}, None)]
    )
    assert [item.key for item in ordered] == ["critical", "clear"]
    now = datetime(2026, 10, 27, tzinfo=UTC)
    assert reader.group_filter("site", None, now) == {"term": {"missing_site": True}}
    assert reader.group_filter("application", "api", now) == {"term": {"application": "api"}}
    for field, key in (("application", None), ("display_status", "open"), ("message", "x")):
        with pytest.raises(AppError) as error:
            reader.group_filter(field, key, now)
        assert error.value.code == "invalid_group"
