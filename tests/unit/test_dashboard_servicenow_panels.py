from pydantic import ValidationError
import pytest

from appchi.configuration.models import (
    DashboardDefinition,
    ServiceNowPanel,
    images_of,
    presets_of,
    referenced_presets_of,
    sanitize_panels,
)

PRESET = "00000000-0000-4000-8000-000000000002"


def panel(n, **fields):
    return {"id": f"00000000-0000-4000-8000-00000000001{n}", "x": 3 * n, "y": 0, "w": 3, "h": 2, **fields}


def test_servicenow_panels_default_to_open_hamal_tickets_and_reference_no_preset():
    """Requirements: REV-65; dashboard operations 2 and 3."""
    board = DashboardDefinition(
        name="Board",
        panels=[
            panel(0, preset_id=PRESET),
            panel(1, type="servicenow", team="Network Ops"),
            panel(2, type="html", html="<p>Hi</p>"),
        ],
    )
    tickets = board.panels[1]
    assert isinstance(tickets, ServiceNowPanel)
    assert (tickets.team, tickets.ticket_state, tickets.detection, tickets.thresholds) == (
        "Network Ops",
        "open",
        "hamal",
        [],
    )
    assert not hasattr(tickets, "preset_id")
    assert presets_of(board.panels) == [PRESET]
    assert referenced_presets_of(board.panels) == [PRESET]
    assert images_of(board.panels) == []
    assert sanitize_panels(board.panels) == []
    assert tickets.model_dump() == {
        "id": "00000000-0000-4000-8000-000000000011",
        "title": None,
        "x": 3,
        "y": 0,
        "w": 3,
        "h": 2,
        "type": "servicenow",
        "team": "Network Ops",
        "ticket_state": "open",
        "detection": "hamal",
        "thresholds": [],
    }


@pytest.mark.parametrize("state", ["open", "in_progress", "both"])
@pytest.mark.parametrize("detection", ["hamal", "direct", "all"])
def test_servicenow_panels_keep_every_state_and_detection(state, detection):
    """Requirements: REV-65; dashboard operations 2 and 3."""
    board = DashboardDefinition(
        name="Board",
        panels=[panel(0, type="servicenow", team="Ops", ticket_state=state, detection=detection)],
    )
    assert (board.panels[0].ticket_state, board.panels[0].detection) == (state, detection)


def test_servicenow_team_names_are_trimmed_normalized_single_line_text():
    """Requirements: REV-65; dashboard operations 3."""
    composed = "Café Ops"
    decomposed = "Café Ops"
    board = DashboardDefinition(name="Board", panels=[panel(0, type="servicenow", team=f"  {decomposed}  ")])
    assert board.panels[0].team == composed
    assert DashboardDefinition(name="B", panels=[panel(0, type="servicenow", team="x" * 200)]).panels[0].team == "x" * 200
    for team in ("", "   ", "x" * 201, "Net\nOps", "Net Ops", "Net​Ops", "Net\x00Ops"):
        with pytest.raises(ValidationError):
            DashboardDefinition(name="Board", panels=[panel(0, type="servicenow", team=team)])


def test_servicenow_thresholds_follow_count_panel_rules():
    """Requirements: REV-65, REV-64; dashboard operations 3."""
    good = [
        {"lower_bound": "1", "color": "amber"},
        {"lower_bound": "5", "color": "#ff0000"},
        {"lower_bound": "10", "color": "dark-red"},
    ]
    board = DashboardDefinition(name="Board", panels=[panel(0, type="servicenow", team="Ops", thresholds=good)])
    assert [t.color for t in board.panels[0].thresholds] == ["amber", "#FF0000", "dark-red"]
    for thresholds in (
        good + [{"lower_bound": "20", "color": "red"}],
        [{"lower_bound": "5", "color": "red"}, {"lower_bound": "5", "color": "blue"}],
        [{"lower_bound": "5", "color": "red"}, {"lower_bound": "1", "color": "blue"}],
        [{"lower_bound": "-1", "color": "red"}],
        [{"lower_bound": "01", "color": "red"}],
        [{"lower_bound": "1", "color": "pink"}],
    ):
        with pytest.raises(ValidationError):
            DashboardDefinition(
                name="Board", panels=[panel(0, type="servicenow", team="Ops", thresholds=thresholds)]
            )


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"team": None},
        {"team": 7},
        {"team": "Ops", "ticket_state": "closed"},
        {"team": "Ops", "ticket_state": "new"},
        {"team": "Ops", "detection": "grafana"},
        {"team": "Ops", "preset_id": PRESET},
        {"team": "Ops", "html": "<p>Hi</p>"},
        {"team": "Ops", "url": "https://example.com"},
    ],
)
def test_servicenow_panels_reject_missing_or_foreign_settings(fields):
    """Requirements: REV-65; dashboard operations 2 and 3."""
    with pytest.raises(ValidationError):
        DashboardDefinition(name="Board", panels=[panel(0, **{"type": "servicenow", **fields})])
