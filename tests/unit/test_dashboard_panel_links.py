from pydantic import ValidationError
import pytest

from appchi.configuration.models import DashboardDefinition, PanelLink

PRESET = "00000000-0000-4000-8000-000000000002"
IMAGE = "00000000-0000-4000-8000-000000000003"
PANELS = {
    "count": {"preset_id": PRESET},
    "table": {"type": "table", "preset_id": PRESET},
    "html": {"type": "html", "html": "<p>Handover</p>"},
    "image": {"type": "image", "image_id": IMAGE},
    "servicenow": {"type": "servicenow", "team": "Payments"},
}


def board(kind="count", **link):
    panel = {
        "id": "00000000-0000-4000-8000-000000000010",
        "x": 0,
        "y": 0,
        "w": 3,
        "h": 2,
        **PANELS[kind],
    }
    if link:
        panel["link"] = link
    return DashboardDefinition(name="Board", panels=[panel])


@pytest.mark.parametrize("kind", sorted(PANELS))
def test_every_panel_type_keeps_its_link(kind):
    """Requirements: REV-66 (with REV-65 ServiceNow panels); dashboard operations 2, 3."""
    saved = board(kind, url="https://runbooks.example/payments", label="Runbook")
    assert saved.panels[0].model_dump()["link"] == {
        "url": "https://runbooks.example/payments",
        "label": "Runbook",
    }


@pytest.mark.parametrize("kind", sorted(PANELS))
def test_panels_without_a_link_have_none(kind):
    """Requirements: REV-66; dashboard operations 14."""
    assert board(kind).panels[0].link is None


@pytest.mark.parametrize(
    "url",
    [
        "http://grafana.internal:3000/d/abc?var=1#panel",
        "https://wiki.example/a%20b",
        "https://" + "a" * 2040,
    ],
)
def test_http_and_https_addresses_are_accepted(url):
    """Requirements: REV-66; dashboard operations 2."""
    assert PanelLink(url=url).url == url


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html,hi",
        "ftp://files.example/report",
        "/dashboards/other",
        "https://",
        "https://wiki.example/a b",
        "https://user:secret@wiki.example/",
        "https://wiki.example/\u00e9",
        "https://wiki.example:99999/",
        "https://" + "a" * 2041,
    ],
)
def test_other_addresses_are_rejected(url):
    """Requirements: REV-66; dashboard operations 2."""
    with pytest.raises(ValidationError):
        PanelLink(url=url)


def test_button_text_is_trimmed_and_blank_is_none():
    """Requirements: REV-66; dashboard operations 3."""
    assert PanelLink(url="https://x.example", label="  Runbook ").label == "Runbook"
    assert PanelLink(url="https://x.example", label="   ").label is None
    assert PanelLink(url="https://x.example", label="a" * 40).label == "a" * 40


@pytest.mark.parametrize("label", ["a" * 41, "Two\nlines", "Tab\there", "Hidden\u200bjoin"])
def test_long_or_multiline_button_text_is_rejected(label):
    """Requirements: REV-66; dashboard operations 3."""
    with pytest.raises(ValidationError):
        PanelLink(url="https://x.example", label=label)


def test_a_link_needs_an_address():
    """Requirements: REV-66; dashboard operations 2."""
    with pytest.raises(ValidationError):
        board(label="Runbook")
    with pytest.raises(ValidationError):
        board(url="https://x.example", target="_self")
