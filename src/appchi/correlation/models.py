"""Versioned correlation editor contracts; configuration cannot supply evidence."""

import re
from typing import Literal
import unicodedata

from pydantic import Field, field_validator, model_validator

from appchi.cel.catalog import FIELDS
from appchi.models import Command, StrictModel, uuid_string
from .evidence import GroupField, validate_group_fields

NAME_PROFILE = "appchi-rule-name-unicode15.1-v1"


def display_name(value: str, maximum=200):
    if unicodedata.unidata_version != "15.1.0":
        raise ValueError("Unsupported rule-name Unicode profile")
    value = unicodedata.normalize("NFC", value)
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value):
        raise ValueError("Single-line names cannot contain control characters")
    value = re.sub(
        r" +", " ", "".join(" " if unicodedata.category(char) == "Zs" else char for char in value)
    ).strip()
    if not 1 <= len(value) <= maximum:
        raise ValueError(f"Use a name of 1–{maximum} Unicode code points")
    return value


def name_key(value):
    return unicodedata.normalize("NFC", value.casefold())


def grouping(fields):
    selected = tuple(
        GroupField(
            name,
            "string"
            if FIELDS.get(name) and FIELDS[name].kind == "enum"
            else FIELDS[name].kind
            if name in FIELDS
            else "invalid",
        )
        for name in fields
    )
    validate_group_fields(selected)
    return selected


class ConditionDefinition(StrictModel):
    id: str
    label: str
    cel: str = Field(min_length=1, max_length=16384)
    _id = field_validator("id")(uuid_string)

    @field_validator("label")
    @classmethod
    def label_name(cls, value):
        return display_name(value, 100)


class Definition(StrictModel):
    name: str
    description: str = Field(default="", max_length=10000)
    severity: Literal["critical", "high", "medium", "low"]
    conditions: list[ConditionDefinition] = Field(min_length=1, max_length=10)
    group_by: list[str] = Field(default_factory=list, max_length=3)
    window_minutes: int = Field(default=10, ge=1, le=1440)
    _name = field_validator("name")(display_name)

    @field_validator("description")
    @classmethod
    def plain_text(cls, value):
        if "\x00" in value or any(unicodedata.category(char) == "Cs" for char in value):
            raise ValueError("Invalid plain text")
        return value

    @field_validator("group_by")
    @classmethod
    def group_fields(cls, value):
        grouping(value)
        return value

    @model_validator(mode="after")
    def unique_conditions(self):
        if len({item.id for item in self.conditions}) != len(self.conditions):
            raise ValueError("Condition IDs must be distinct")
        if len({name_key(item.label) for item in self.conditions}) != len(self.conditions):
            raise ValueError("Condition labels must be distinct")
        return self


class Create(Definition):
    command_id: str
    _command = field_validator("command_id")(uuid_string)


class Replace(Create):
    expected_revision: str
    _revision = field_validator("expected_revision")(Command.revision.__func__)


class TestRequest(Definition):
    alert_id: str
    _alert = field_validator("alert_id")(uuid_string)
