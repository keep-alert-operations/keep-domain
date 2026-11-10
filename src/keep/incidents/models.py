from typing import Literal
from pydantic import Field, field_validator
from keep.models import Command, StrictModel, uuid_string


class IncidentCreate(StrictModel):
    command_id: str
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    severity: Literal["critical", "high", "medium", "low"]
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    _command = field_validator("command_id")(uuid_string)

    @field_validator("title")
    @classmethod
    def valid_title(cls, value):
        value = value.strip()
        if not value or any(ord(c) < 32 or c in "\u2028\u2029" for c in value):
            raise ValueError("Single-line title required")
        return value

    @field_validator("alert_ids")
    @classmethod
    def selection(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Duplicate alert selection")
        for item in value:
            uuid_string(item)
        return value


class IncidentStatus(Command):
    status: Literal["open", "investigating", "resolved"]


class IncidentAssignment(Command):
    assignee_id: str | None

    @field_validator("assignee_id")
    @classmethod
    def eligible_id(cls, value):
        return uuid_string(value) if value is not None else None


class IncidentContent(Command):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(max_length=10000)
    _title = field_validator("title")(IncidentCreate.valid_title.__func__)


class IncidentLinks(Command):
    alert_ids: list[str] = Field(min_length=1, max_length=100)
    _selection = field_validator("alert_ids")(IncidentCreate.selection.__func__)


class IncidentMove(StrictModel):
    command_id: str
    source_id: str
    destination_id: str
    source_revision: str
    destination_revision: str
    _revisions = field_validator("source_revision", "destination_revision")(
        Command.revision.__func__
    )
    alert_ids: list[str] = Field(min_length=1, max_length=100)
    _ids = field_validator("command_id", "source_id", "destination_id")(uuid_string)
    _selection = field_validator("alert_ids")(IncidentCreate.selection.__func__)
