from pydantic import ValidationError
import pytest

from keep.config import Settings
from keep.configuration.grafana import grafana_url_problem, parse_grafana_origins
from keep.configuration.models import (
    DashboardDefinition,
    GrafanaPanel,
    presets_of,
    referenced_presets_of,
    sanitize_panels,
)

KEEP = "https://keep.example.com"
PANEL = "https://grafana.example.com/d-solo/ck81x/checkout?orgId=1&panelId=4"


def panel(n, **fields):
    return {"id": f"00000000-0000-4000-8000-00000000001{n}", "x": 3 * n, "y": 0, "w": 3, "h": 2, **fields}


def test_grafana_panels_keep_their_address_and_reference_nothing():
    """Requirements: REV-68; dashboard operations 2 and 3."""
    board = DashboardDefinition(
        name="Board",
        panels=[
            panel(0, type="grafana", url=PANEL),
            panel(1, type="grafana", url=PANEL, link={"url": "https://grafana.example.com/d/ck81x"}),
        ],
    )
    grafana = board.panels[0]
    assert isinstance(grafana, GrafanaPanel)
    assert (grafana.url, grafana.title, grafana.link) == (PANEL, None, None)
    assert not hasattr(grafana, "preset_id") and not hasattr(grafana, "thresholds")
    assert presets_of(board.panels) == referenced_presets_of(board.panels) == []
    assert sanitize_panels(board.panels) == []
    assert board.panels[1].link.url == "https://grafana.example.com/d/ck81x"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "grafana.example.com/d-solo/a",
        "https:grafana.example.com/d-solo/a",
        "ftp://grafana.example.com/d-solo/a",
        "javascript:alert(1)",
        "https:///d-solo/a",
        "https://admin:secret@grafana.example.com/d-solo/a",
        "https://admin@grafana.example.com/d-solo/a",
        "https://grafana.example.com/d-solo/a b",
        "https://grafana.example.com/d-solo/é",
        "https://grafana.example.com:99999/d-solo/a",
        "https://grafana.example.com/" + "x" * 2030,
    ],
)
def test_grafana_panel_addresses_must_be_absolute_http_without_credentials(url):
    """Requirements: REV-68; dashboard operations 3 (address form, checks 1-4, 7, 11)."""
    with pytest.raises(ValidationError):
        GrafanaPanel(**panel(0, type="grafana", url=url))


def test_grafana_panels_need_an_address_and_take_no_thresholds():
    """Requirements: REV-68; dashboard operations 3."""
    with pytest.raises(ValidationError):
        GrafanaPanel(**panel(0, type="grafana"))
    with pytest.raises(ValidationError):
        GrafanaPanel(**panel(0, type="grafana", url=PANEL, thresholds=[]))


def test_allowed_grafana_list_keeps_https_origins_with_base_paths():
    """Requirements: REV-68; dashboard operations 14 (allowed Grafana configuration)."""
    origins = parse_grafana_origins(
        " https://Grafana.Example.com/ , https://tools.example.com/grafana/,"
        "https://grafana.example.com:443,,https://tools.example.com/grafana",
        KEEP,
    )
    assert origins.enabled
    assert origins.allowed == [
        {"origin": "https://grafana.example.com", "path_prefix": ""},
        {"origin": "https://tools.example.com", "path_prefix": "/grafana"},
    ]
    assert origins.ignored == []


@pytest.mark.parametrize(
    "entry",
    [
        "http://grafana.example.com",
        "grafana.example.com",
        "https://user:pw@grafana.example.com",
        "https://grafana.example.com/?orgId=1",
        "https://grafana.example.com/#x",
        "https://keep.example.com",
        "https://keep.example.com:443/grafana",
        "https://grafana .example.com",
        "ftp://grafana.example.com",
        "https://grafana.example.com:99999",
    ],
)
def test_unusable_allowed_grafana_entries_are_ignored_with_a_reason(entry):
    """Requirements: REV-68; dashboard operations 14."""
    origins = parse_grafana_origins(f"{entry},https://ok.example.com", KEEP)
    assert origins.allowed == [{"origin": "https://ok.example.com", "path_prefix": ""}]
    assert [item["entry"] for item in origins.ignored] == [entry]
    assert origins.ignored[0]["reason"]


def test_loopback_http_grafana_is_allowed_only_in_development():
    """Requirements: REV-68; dashboard operations 14 (local development)."""
    local = "http://127.0.0.1:58091"
    assert parse_grafana_origins(local, KEEP, "development").allowed == [
        {"origin": local, "path_prefix": ""}
    ]
    assert not parse_grafana_origins(local, KEEP, "production").enabled
    assert not parse_grafana_origins("http://grafana.example.com", KEEP, "development").enabled
    assert not parse_grafana_origins(None, KEEP).enabled
    assert not parse_grafana_origins(" , ", KEEP).enabled


ORIGINS = parse_grafana_origins("https://grafana.example.com,https://tools.example.com/grafana", KEEP)


@pytest.mark.parametrize(
    ("url", "problem"),
    [
        (PANEL, None),
        ("https://GRAFANA.example.com:443/d-solo/a/b?panelId=1", None),
        ("https://tools.example.com/grafana/d-solo/a/b?panelId=1", None),
        ("https://keep.example.com/d-solo/a", "Keep's own pages can't be shown in a Grafana panel."),
        ("http://grafana.example.com/d-solo/a", "Keep is served over https, so the panel address must be https too."),
        ("https://grafana-old.example.com/d-solo/a", "grafana-old.example.com isn't an allowed Grafana."),
        ("https://grafana.example.com:3000/d-solo/a", "grafana.example.com:3000 isn't an allowed Grafana."),
        ("https://tools.example.com/d-solo/a", "tools.example.com isn't an allowed Grafana."),
        ("https://tools.example.com/grafanax/d-solo/a", "tools.example.com isn't an allowed Grafana."),
        ("https://grafana.example.com/d/ck81x/checkout?viewPanel=4", "Use a single-panel address from Share › Embed. Whole dashboards can't be shown."),
        ("https://tools.example.com/grafana/x/d-solo/a", "Use a single-panel address from Share › Embed. Whole dashboards can't be shown."),
    ],
)
def test_grafana_addresses_are_checked_against_the_allowed_list_in_order(url, problem):
    """Requirements: REV-68; dashboard operations 3 (checks 5-10)."""
    assert grafana_url_problem(url, ORIGINS, KEEP) == problem


def test_grafana_panels_are_turned_off_without_an_allowed_grafana():
    """Requirements: REV-68; dashboard operations 14."""
    off = parse_grafana_origins("", KEEP)
    assert grafana_url_problem(PANEL, off, KEEP) == "Grafana panels are turned off."
    # Keep's own origin is refused first, whatever the list says.
    assert grafana_url_problem(KEEP + "/d-solo/a", off, KEEP).startswith("Keep's own")


def test_settings_read_the_allowed_grafana_list(monkeypatch):
    """Requirements: REV-68; dashboard operations 14."""
    monkeypatch.setenv("KEEP_GRAFANA_PANEL_ORIGINS", "https://grafana.example.com")
    settings = Settings(
        deployment_epoch="test",
        database_url="postgresql://x",
        wrapping_key="A" * 43 + "=",
    )
    assert settings.grafana_panel_origins == "https://grafana.example.com"
