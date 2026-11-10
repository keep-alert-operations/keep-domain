from pydantic import ValidationError
import pytest

from keep.configuration.html import MAX_HTML, removals, sanitize
from keep.configuration.models import (
    DashboardDefinition,
    HtmlPanel,
    Panel,
    presets_of,
    sanitize_panels,
)

PRESET = "00000000-0000-4000-8000-000000000002"


def panel(n, **fields):
    return {"id": f"00000000-0000-4000-8000-00000000001{n}", "x": 3 * n, "y": 0, "w": 3, "h": 2, **fields}


def test_a_panel_without_type_is_a_count_panel():
    """Requirements: REV-57; dashboard operations 2."""
    board = DashboardDefinition(name="Board", panels=[panel(0, preset_id=PRESET)])
    assert isinstance(board.panels[0], Panel)
    assert board.panels[0].model_dump()["type"] == "count"


def test_html_panels_mix_with_counts_and_reference_no_preset():
    """Requirements: REV-57; dashboard operations 2 and 14."""
    board = DashboardDefinition(
        name="Board",
        panels=[
            panel(0, preset_id=PRESET),
            panel(1, type="html", title="Notes", html="<p>Hi</p>"),
            panel(2, type="count", preset_id=PRESET),
        ],
    )
    assert isinstance(board.panels[1], HtmlPanel)
    assert presets_of(board.panels) == [PRESET]
    assert presets_of([board.panels[1]]) == []


@pytest.mark.parametrize(
    "fields",
    [
        {"type": "html", "html": "<p>Hi</p>", "preset_id": PRESET},
        {"type": "html", "html": "<p>Hi</p>", "thresholds": []},
        {"type": "html"},
        {"type": "count"},
        {"type": "chart", "html": "<p>Hi</p>"},
    ],
)
def test_each_type_takes_only_its_own_settings(fields):
    """Requirements: REV-57; dashboard operations 2 and 5."""
    with pytest.raises(ValidationError):
        DashboardDefinition(name="Board", panels=[panel(0, **fields)])


def test_layout_and_title_rules_apply_to_html_panels():
    """Requirements: REV-57; dashboard operations 3 and 4."""
    with pytest.raises(ValidationError, match="Panel exceeds grid"):
        HtmlPanel(**{**panel(0), "x": 10}, type="html", html="")
    with pytest.raises(ValidationError, match="Title exceeds"):
        HtmlPanel(**panel(0), type="html", title="x" * 121, html="")


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("<p>Hi<script>alert(1)</script></p>", "<p>Hi</p>"),
        ('<p onclick="x()">Hi</p>', "<p>Hi</p>"),
        ('<a href="javascript:alert(1)">x</a>', '<a target="_blank" rel="noopener noreferrer">x</a>'),
        ('<a href="data:text/html,x">x</a>', '<a target="_blank" rel="noopener noreferrer">x</a>'),
        ('<a href="/internal">x</a>', '<a target="_blank" rel="noopener noreferrer">x</a>'),
        (
            '<a href="https://example.com">x</a>',
            '<a href="https://example.com" target="_blank" rel="noopener noreferrer">x</a>',
        ),
        ('<img src="https://example.com/a.png">', ""),
        ("<iframe src='https://example.com'></iframe><form><input></form>", ""),
        ("<h1>Big</h1><h3>Small</h3>", "Big<h3>Small</h3>"),
        ("<!-- note --><p>Hi</p>", "<p>Hi</p>"),
        (
            '<p style="color: red; position: fixed; background-color: url(x)">Hi</p>',
            '<p style="color: red">Hi</p>',
        ),
        ('<p style="position: fixed">Hi</p>', "<p>Hi</p>"),
        ('<p style="font-size: 20px">Hi</p>', '<p style="font-size: 20px">Hi</p>'),
        ('<p style="font-size: url(x)">Hi</p>', "<p>Hi</p>"),
    ],
)
def test_sanitizing_keeps_only_the_allowlist(raw, clean):
    """Requirements: REV-57; dashboard operations 5."""
    assert sanitize(raw) == clean


def test_stored_html_is_sanitized_and_bounded():
    """Requirements: REV-57; dashboard operations 5."""
    stored = HtmlPanel(**panel(0), type="html", html='<p onclick="x()">Hi</p>')
    # Validation leaves the raw text alone; sanitizing waits for authorization.
    assert stored.html == '<p onclick="x()">Hi</p>'
    sanitize_panels([stored])
    assert stored.html == "<p>Hi</p>"
    sanitize_panels([HtmlPanel(**panel(0), type="html", html="a" * MAX_HTML)])
    with pytest.raises(ValueError, match="16,000 characters"):
        sanitize_panels([HtmlPanel(**panel(0), type="html", html="a" * (MAX_HTML + 1))])
    # Removed parts do not count toward the limit.
    sanitize_panels(
        [HtmlPanel(**panel(0), type="html", html="a" * MAX_HTML + "<script>" + "b" * 100 + "</script>")]
    )
    with pytest.raises(ValidationError):
        HtmlPanel(**panel(0), type="html", html="a" * 65_537)


def test_removals_name_each_part_with_its_line():
    """Requirements: REV-57; dashboard operations 14."""
    raw = '<p>\n<a href="https://x" onclick="t()">x</a>\n</p>\n<script>t()</script>\n<p style="color: red; position: fixed">y</p>'
    assert removals(raw) == [
        {"line": 2, "what": "onclick attribute"},
        {"line": 4, "what": "<script> element"},
        {"line": 5, "what": "position style"},
    ]
    assert removals('<a href="/x">x</a>') == [{"line": 1, "what": "relative link"}]
    assert removals("<p>Fine</p>") == []


def test_sanitizing_reports_removals_per_panel_and_nothing_for_stored_html():
    """Requirements: REV-57; dashboard operations 14."""
    counted = Panel(**panel(0), preset_id=PRESET)
    noted = HtmlPanel(**panel(1), type="html", html='<p onclick="x()"><a href="https://e.com">Hi</a></p>')
    assert sanitize_panels([counted, noted]) == [
        {"panel_id": noted.id, "line": 1, "what": "onclick attribute"}
    ]
    # Reopening a saved panel reports nothing, though stored links carry target and rel.
    assert removals(noted.html) == []
    assert sanitize_panels([noted]) == []


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ('<p style="color: red /*; margin: */ position: fixed">x</p>', "<p>x</p>"),
        ('<p style="color: red; background-color: URL(x)">x</p>', '<p style="color: red">x</p>'),
        (r'<p style="color: re\64">x</p>', "<p>x</p>"),
        ('<p style="margin: 0 } p { position: fixed">x</p>', "<p>x</p>"),
        ('<a href="jav&#x09;ascript:alert(1)">x</a>', '<a target="_blank" rel="noopener noreferrer">x</a>'),
        ('<a href="//evil.example">x</a>', '<a target="_blank" rel="noopener noreferrer">x</a>'),
        ("<svg><script>alert(1)</script></svg>", ""),
        ('<p id="session" class="btn">x</p>', "<p>x</p>"),
    ],
)
def test_sanitizing_resists_known_bypasses(raw, clean):
    """Requirements: REV-57; dashboard operations 5."""
    assert sanitize(raw) == clean
