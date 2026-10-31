import unicodedata
from typing import Literal
from pydantic import Field, field_validator, model_validator

from appchi.models import StrictModel, Command, uuid_string

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
    "message",
    "suppressed",
    "occurrence_id",
    "acknowledged_by",
    "acknowledged_at",
    "active_incident_id",
}
# REV-44; appchi.search.reader.GROUPABLE holds the same fields for execution.
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


class Threshold(StrictModel):
    lower_bound: str
    color: Literal["blue", "green", "amber", "red"]

    @field_validator("lower_bound")
    @classmethod
    def count(cls, value):
        if not value.isascii() or not value.isdigit() or str(int(value)) != value:
            raise ValueError("Canonical nonnegative integer required")
        return value


class Panel(StrictModel):
    id: str
    preset_id: str
    title: str | None = None
    x: int = Field(ge=0)
    y: int = Field(ge=0)
    w: int = Field(ge=3, le=12)
    h: int = Field(ge=2)
    thresholds: list[Threshold] = Field(default_factory=list, max_length=3)
    _id = field_validator("id", "preset_id")(uuid_string)

    @model_validator(mode="after")
    def valid_layout(self):
        if self.x + self.w > 12 or self.y + self.h > 100:
            raise ValueError("Panel exceeds grid")
        bounds = [int(item.lower_bound) for item in self.thresholds]
        if sorted(set(bounds)) != bounds:
            raise ValueError("Thresholds must increase strictly")
        if self.title is not None:
            self.title = name(self.title)
            if len(self.title) > 120:
                raise ValueError("Title exceeds 120 characters")
        return self


class DashboardDefinition(StrictModel):
    name: str
    panels: list[Panel] = Field(max_length=24)
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
