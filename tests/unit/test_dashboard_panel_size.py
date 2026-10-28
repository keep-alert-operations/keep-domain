from pydantic import ValidationError
import pytest

from appchi.configuration.models import Panel

BASE = {
    "id": "00000000-0000-4000-8000-000000000001",
    "preset_id": "00000000-0000-4000-8000-000000000002",
    "x": 0,
    "y": 0,
}


def test_width_grows_one_column_at_a_time_to_the_full_row():
    """Requirements: REV-50; dashboard operations 4."""
    for w in range(3, 13):
        assert Panel(**BASE, w=w, h=2).w == w
    for w in (2, 13):
        with pytest.raises(ValidationError):
            Panel(**BASE, w=w, h=2)
    with pytest.raises(ValidationError, match="Panel exceeds grid"):
        Panel(**{**BASE, "x": 4}, w=9, h=2)


def test_height_has_no_maximum_below_the_grid_bound():
    """Requirements: REV-50; dashboard operations 4."""
    assert Panel(**BASE, w=3, h=5).h == 5
    assert Panel(**BASE, w=3, h=100).h == 100
    with pytest.raises(ValidationError):
        Panel(**BASE, w=3, h=1)
    with pytest.raises(ValidationError, match="Panel exceeds grid"):
        Panel(**{**BASE, "y": 1}, w=3, h=100)
