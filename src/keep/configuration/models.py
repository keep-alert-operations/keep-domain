import unicodedata
from typing import Annotated, Literal
from urllib.parse import urlsplit
from pydantic import Discriminator, Field, Tag, field_validator, model_validator

from keep.configuration import html
from keep.models import StrictModel, Command, uuid_string

SORTABLE = {
    "application",
    "component",
    "node_name",
    "site",
    "operator",
    "name",
    "severity",
    "status",
    "time_created",
    "first_received_at",
    "timestamp",
    "occurrence_number",
    "opened_at",
    "resolved_at",
    "acknowledged",
    "assignee_id",
}
COLUMNS = SORTABLE | {
    "display_status",
    "id",
    "tenant_id",
    "schema_version",
    "key_field",
    "impact",
    "runbook_url",
    "provider",
    "alert_rule_url",
    "message",
    "suppressed",
    "occurrence_id",
    "acknowledged_by",
    "acknowledged_at",
    "active_incident_id",
}
# REV-44; keep.search.reader.GROUPABLE holds the same fields for execution.
GROUPABLE = {
    "severity",
    "display_status",
    "application",
    "component",
    "node_name",
    "site",
    "name",
    "assignee_id",
    "active_incident_id",
}


def name(value):
    display = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(display) <= 128 or any(
        unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in display
    ):
        raise ValueError("Use a 1–128 character name without control characters")
    return display


def name_key(value):
    return unicodedata.normalize("NFC", unicodedata.normalize("NFD", value).casefold())


class Sort(StrictModel):
    field: str
    direction: Literal["asc", "desc"]

    @field_validator("field")
    @classmethod
    def field_name(cls, value):
        value = "timestamp" if value == "last_received_at" else value
        if value not in SORTABLE:
            raise ValueError("Unsupported sort")
        return value


class PresetDefinition(StrictModel):
    name: str
    cel: str
    sort: list[Sort] = Field(min_length=1, max_length=3)
    columns: list[str] = Field(min_length=1, max_length=30)
    group_by: str | None = None
    # Sound the alarm while the results page has alerts (REV-58).
    noisy: bool = False
    _name = field_validator("name")(name)

    @field_validator("group_by")
    @classmethod
    def grouping(cls, value):
        if value is not None and value not in GROUPABLE:
            raise ValueError("Unsupported grouping")
        return value

    @field_validator("columns")
    @classmethod
    def column_names(cls, values):
        values = ["timestamp" if value == "last_received_at" else value for value in values]
        if len(set(values)) != len(values) or set(values) - COLUMNS:
            raise ValueError("Duplicate or unsupported columns")
        return values

    @model_validator(mode="after")
    def sorts(self):
        if len({item.field for item in self.sort}) != len(self.sort):
            raise ValueError("Duplicate sorts")
        return self


# REV-64: a palette name (eight hues in five shades; the middle shade is the hue
# alone) or a custom #RRGGBB color, stored upper case.
THRESHOLD_HUES = ("red", "orange", "amber", "green", "teal", "blue", "purple", "gray")
THRESHOLD_SHADES = ("lightest-", "light-", "", "dark-", "darkest-")
THRESHOLD_PALETTE = frozenset(
    shade + hue for hue in THRESHOLD_HUES for shade in THRESHOLD_SHADES
)
THRESHOLD_COLOR = (
    r"^(#[0-9A-Fa-f]{6}|((lightest|light|dark|darkest)-)?"
    r"(red|orange|amber|green|teal|blue|purple|gray))$"
)


class Threshold(StrictModel):
    lower_bound: str
    color: Annotated[str, Field(pattern=THRESHOLD_COLOR)]

    @field_validator("color")
    @classmethod
    def canonical_color(cls, value):
        return value.upper() if value.startswith("#") else value

    @field_validator("lower_bound")
    @classmethod
    def count(cls, value):
        if not value.isascii() or not value.isdigit() or str(int(value)) != value:
            raise ValueError("Canonical nonnegative integer required")
        return value


class PanelLink(StrictModel):
    """A panel's link button: an http(s) address and optional button text (REV-66)."""

    url: str = Field(max_length=2048)
    label: str | None = None

    @field_validator("url")
    @classmethod
    def address(cls, value):
        if not value.isascii() or any(c.isspace() or not c.isprintable() for c in value):
            raise ValueError("Use a link without spaces or control characters")
        try:
            parts = urlsplit(value)
            parts.port
        except ValueError:
            raise ValueError("Use a valid link address") from None
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("Use a full link that starts with https:// or http://")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Links cannot contain a user name or password")
        return value

    @field_validator("label")
    @classmethod
    def text(cls, value):
        if value is None:
            return None
        value = unicodedata.normalize("NFC", value.strip())
        if not value:
            return None
        if len(value) > 40 or any(
            unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in value
        ):
            raise ValueError("Use single-line button text of up to 40 characters")
        return value


class PanelLayout(StrictModel):
    id: str
    title: str | None = None
    x: int = Field(ge=0)
    y: int = Field(ge=0)
    w: int = Field(ge=3, le=12)
    h: int = Field(ge=2)
    # Every panel type may have a link button (REV-66).
    link: PanelLink | None = None
    _id = field_validator("id")(uuid_string)

    @model_validator(mode="after")
    def valid_layout(self):
        if self.x + self.w > 12 or self.y + self.h > 100:
            raise ValueError("Panel exceeds grid")
        if self.title is not None:
            self.title = name(self.title)
            if len(self.title) > 120:
                raise ValueError("Title exceeds 120 characters")
        return self


class Panel(PanelLayout):
    """A preset count panel; a panel without ``type`` is one (REV-57)."""

    type: Literal["count"] = "count"
    preset_id: str
    thresholds: list[Threshold] = Field(default_factory=list, max_length=3)
    _preset = field_validator("preset_id")(uuid_string)

    @model_validator(mode="after")
    def increasing(self):
        return increasing_thresholds(self)


def increasing_thresholds(panel):
    """Require a panel's threshold lower bounds to increase strictly."""
    bounds = [int(item.lower_bound) for item in panel.thresholds]
    if sorted(set(bounds)) != bounds:
        raise ValueError("Thresholds must increase strictly")
    return panel


class HtmlPanel(PanelLayout):
    """A panel showing HTML; it references no preset (REV-57).

    Validation bounds only the raw size. Callers sanitize with ``sanitize_panels``
    after authorizing the request, so unauthenticated bodies are never parsed.
    """

    type: Literal["html"]
    html: str = Field(max_length=65_536)


class ImagePanel(PanelLayout):
    """A panel showing an uploaded image or an https image address (REV-62)."""

    type: Literal["image"]
    image_id: str | None = None
    url: str | None = Field(default=None, max_length=2048)
    fit: Literal["contain", "cover"] = "contain"
    alt: str | None = None

    @field_validator("image_id")
    @classmethod
    def image(cls, value):
        return None if value is None else uuid_string(value)

    @field_validator("url")
    @classmethod
    def address(cls, value):
        if value is None:
            return None
        if not value.isascii() or any(c.isspace() or not c.isprintable() for c in value):
            raise ValueError("Use an image address without spaces or control characters")
        try:
            parts = urlsplit(value)
            parts.port
        except ValueError:
            raise ValueError("Use a valid https image address") from None
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("Use an address that starts with https://")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Image addresses cannot contain a user name or password")
        return value

    @field_validator("alt")
    @classmethod
    def description(cls, value):
        if value is None:
            return None
        value = unicodedata.normalize("NFC", value.strip())
        if not value:
            return None
        if len(value) > 300 or any(
            unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in value
        ):
            raise ValueError("Use a single-line description of up to 300 characters")
        return value

    @model_validator(mode="after")
    def one_source(self):
        if (self.image_id is None) == (self.url is None):
            raise ValueError("An image panel needs exactly one of image_id or url")
        return self


def images_of(panels):
    """Uploaded image IDs referenced by image panels, in first-use order (REV-62)."""
    return list(dict.fromkeys(p.image_id for p in panels if p.type == "image" and p.image_id))


class TablePanel(PanelLayout):
    """A panel listing its preset's latest alerts, newest first (REV-63).

    It references a preset like a count panel and shows ``rows`` alerts in the
    preset's saved columns; it has no thresholds and is never counted.
    """

    type: Literal["table"]
    preset_id: str
    rows: int = Field(default=10, ge=1, le=50)
    _preset = field_validator("preset_id")(uuid_string)


def ticket_team(value):
    """A ServiceNow team name: trimmed NFC text on one line, 1–200 characters (REV-65)."""
    value = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(value) <= 200 or any(
        unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in value
    ):
        raise ValueError("Use a single-line team name of 1–200 characters")
    return value


TicketState = Literal["open", "in_progress", "both"]
TicketDetection = Literal["hamal", "direct", "all"]


class ServiceNowPanel(PanelLayout):
    """A panel showing a team's ServiceNow ticket count (REV-65).

    The API server asks the deployment's ticket counting service for the count of
    ``team``'s tickets in ``ticket_state`` found by ``detection``. It references no
    preset and is never part of a count batch; ``thresholds`` color the count like
    a count panel's.
    """

    type: Literal["servicenow"]
    team: str
    ticket_state: TicketState = "open"
    detection: TicketDetection = "hamal"
    thresholds: list[Threshold] = Field(default_factory=list, max_length=3)
    _team = field_validator("team")(ticket_team)

    @model_validator(mode="after")
    def increasing(self):
        return increasing_thresholds(self)


def sanitize_panels(panels):
    """Sanitize HTML panels in place and return what sanitizing removed."""
    removed = []
    for panel in panels:
        if panel.type != "html":
            continue
        removed += [{"panel_id": panel.id, **item} for item in html.removals(panel.html)]
        panel.html = html.sanitize(panel.html)
        if len(panel.html) > html.MAX_HTML:
            raise ValueError(f"HTML content exceeds {html.MAX_HTML:,} characters")
    return removed


def panel_type(value):
    if isinstance(value, dict):
        return value.get("type", "count")
    return getattr(value, "type", "count")


AnyPanel = Annotated[
    Annotated[Panel, Tag("count")]
    | Annotated[HtmlPanel, Tag("html")]
    | Annotated[ImagePanel, Tag("image")]
    | Annotated[TablePanel, Tag("table")]
    | Annotated[ServiceNowPanel, Tag("servicenow")],
    Discriminator(panel_type),
]


def presets_of(panels):
    """Preset IDs counted by count panels, in first-use order."""
    return list(dict.fromkeys(p.preset_id for p in panels if p.type == "count"))


def referenced_presets_of(panels):
    """Preset IDs any panel references (count and table panels), in first-use order."""
    return list(dict.fromkeys(p.preset_id for p in panels if p.type in ("count", "table")))


class DashboardDefinition(StrictModel):
    name: str
    panels: list[AnyPanel] = Field(max_length=24)
    _name = field_validator("name")(name)

    @model_validator(mode="after")
    def layout(self):
        if len({p.id for p in self.panels}) != len(self.panels):
            raise ValueError("Duplicate panel IDs")
        for i, a in enumerate(self.panels):
            for b in self.panels[i + 1 :]:
                if a.x < b.x + b.w and b.x < a.x + a.w and a.y < b.y + b.h and b.y < a.y + a.h:
                    raise ValueError("Panels overlap")
        return self


class PresetCreate(PresetDefinition):
    command_id: str
    _command = field_validator("command_id")(uuid_string)


class PresetReplace(PresetCreate):
    expected_revision: str
    _revision = field_validator("expected_revision")(Command.revision.__func__)


class DashboardCreate(DashboardDefinition):
    command_id: str
    _command = field_validator("command_id")(uuid_string)


class DashboardReplace(DashboardCreate):
    expected_revision: str
    _revision = field_validator("expected_revision")(Command.revision.__func__)
