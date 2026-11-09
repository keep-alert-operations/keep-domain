from pydantic import ValidationError
import pytest

from appchi.configuration.models import (
    THRESHOLD_PALETTE,
    DashboardDefinition,
    Threshold,
)

PRESET = "00000000-0000-4000-8000-000000000002"


def board(*colors):
    thresholds = [
        {"lower_bound": str(index), "color": color} for index, color in enumerate(colors)
    ]
    return DashboardDefinition(
        name="Board",
        panels=[
            {
                "id": "00000000-0000-4000-8000-000000000010",
                "x": 0,
                "y": 0,
                "w": 3,
                "h": 2,
                "preset_id": PRESET,
                "thresholds": thresholds,
            }
        ],
    )


def test_palette_has_eight_hues_in_five_shades():
    """Requirements: REV-64; dashboard operations 5."""
    assert len(THRESHOLD_PALETTE) == 40
    assert {"blue", "green", "amber", "red"} <= THRESHOLD_PALETTE
    assert {"lightest-teal", "light-purple", "dark-gray", "darkest-orange"} <= THRESHOLD_PALETTE


@pytest.mark.parametrize("color", sorted(THRESHOLD_PALETTE))
def test_every_palette_name_is_accepted(color):
    """Requirements: REV-64; dashboard operations 5."""
    assert Threshold(lower_bound="1", color=color).color == color


def test_former_colors_keep_their_names():
    """Requirements: REV-64; dashboard operations 5."""
    saved = board("blue", "green", "amber")
    assert [t.color for t in saved.panels[0].thresholds] == ["blue", "green", "amber"]


def test_custom_hex_is_stored_upper_case():
    """Requirements: REV-64; dashboard operations 5."""
    saved = board("#e0569b", "#13918B")
    assert [t.color for t in saved.panels[0].thresholds] == ["#E0569B", "#13918B"]
    assert saved.panels[0].model_dump()["thresholds"][0]["color"] == "#E0569B"


@pytest.mark.parametrize(
    "color",
    [
        "pink",
        "Blue",
        "semi-dark-red",
        "dark-",
        "#abc",
        "#1234567",
        "E0569B",
        "#GG0000",
        "rgb(1,2,3)",
        "var(--primary)",
        "#E0569B;background:red",
        " #E0569B",
        "",
    ],
)
def test_other_colors_are_rejected(color):
    """Requirements: REV-64; dashboard operations 5 (no arbitrary CSS)."""
    with pytest.raises(ValidationError):
        Threshold(lower_bound="1", color=color)
