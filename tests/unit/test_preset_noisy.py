from pydantic import ValidationError
import pytest

from keep.configuration.models import PresetCreate, PresetDefinition

BASE = {
    "name": "Night on-call",
    "cel": "true",
    "sort": [{"field": "timestamp", "direction": "desc"}],
    "columns": ["severity", "message"],
}


def test_noisy_is_an_optional_strict_boolean():
    """Requirements: REV-58; preset operations 3 and 16."""
    assert PresetDefinition(**BASE).noisy is False
    assert PresetDefinition(**BASE, noisy=True).noisy is True
    created = PresetCreate(**BASE, noisy=True, command_id="00000000-0000-4000-8000-000000000001")
    assert created.model_dump()["noisy"] is True
    for value in ("true", 1, None):
        with pytest.raises(ValidationError):
            PresetDefinition(**BASE, noisy=value)
