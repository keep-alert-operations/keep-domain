from pydantic import ValidationError
import pytest

from keep.configuration.models import (
    DashboardDefinition,
    HtmlPanel,
    Panel,
    TablePanel,
    presets_of,
    referenced_presets_of,
    sanitize_panels,
)

PRESET = "00000000-0000-4000-8000-000000000002"
OTHER = "00000000-0000-4000-8000-000000000003"


def panel(n, **fields):
    return {"id": f"00000000-0000-4000-8000-00000000001{n}", "x": 3 * n, "y": 0, "w": 3, "h": 2, **fields}


def test_table_panels_reference_a_preset_and_default_to_ten_rows():
    """Requirements: REV-63; dashboard operations 2 and 14."""
    board = DashboardDefinition(
        name="Board",
        panels=[
            panel(0, preset_id=PRESET),
            panel(1, type="table", preset_id=OTHER, title="Latest"),
            panel(2, type="html", html="<p>Hi</p>"),
        ],
    )
    table = board.panels[1]
    assert isinstance(board.panels[0], Panel)
    assert isinstance(table, TablePanel)
    assert isinstance(board.panels[2], HtmlPanel)
    assert table.rows == 10
    assert table.model_dump() == {
        "id": table.id,
        "title": "Latest",
        "x": 3,
        "y": 0,
        "w": 3,
        "h": 2,
        "link": None,
        "type": "table",
        "preset_id": OTHER,
        "rows": 10,
    }
    # Counts consider count panels only; references include table panels.
    assert presets_of(board.panels) == [PRESET]
    assert referenced_presets_of(board.panels) == [PRESET, OTHER]
    assert sanitize_panels(board.panels) == []


@pytest.mark.parametrize("rows", [1, 25, 50])
def test_table_rows_accept_one_through_fifty(rows):
    """Requirements: REV-63."""
    board = DashboardDefinition(name="Board", panels=[panel(0, type="table", preset_id=PRESET, rows=rows)])
    assert board.panels[0].rows == rows


@pytest.mark.parametrize(
    "fields",
    [
        {"rows": 0},
        {"rows": 51},
        {"rows": 2.5},
        {"rows": "ten"},
        {"preset_id": None},
        {"preset_id": "not-a-uuid"},
        {"thresholds": [{"lower_bound": "1", "color": "red"}]},
        {"html": "<p>Hi</p>"},
    ],
)
def test_table_panels_reject_invalid_settings(fields):
    """Requirements: REV-63; dashboard operations 2."""
    with pytest.raises(ValidationError):
        DashboardDefinition(name="Board", panels=[panel(0, **{"type": "table", "preset_id": PRESET, **fields})])


def test_table_panels_require_a_preset():
    """Requirements: REV-63; dashboard operations 2."""
    with pytest.raises(ValidationError):
        DashboardDefinition(name="Board", panels=[panel(0, type="table")])
