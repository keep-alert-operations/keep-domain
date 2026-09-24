from typing import Annotated, Literal
import unicodedata

from pydantic import Field, field_validator, model_validator

from appchi.models import Command, StrictModel, uuid_string


def maintenance_name(value: str) -> str:
    value = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(value) <= 200 or any(
        unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in value
    ):
        raise ValueError("Use a single-line name of 1–200 code points.")
    return value


def reason_text(value):
    if "\x00" in value or any(unicodedata.category(c) == "Cs" for c in value):
        raise ValueError("Invalid plain text.")
    return value


class Definition(StrictModel):
    name: str = Field(max_length=200)
    reason: str = Field(default="", max_length=10000)
    cel: str = Field(min_length=1, max_length=16384)
    timezone: str = Field(min_length=1, max_length=128)
    start_local: str
    end_local: str
    start_occurrence: Literal["first", "second"] | None = None
    end_occurrence: Literal["first", "second"] | None = None
    _name = field_validator("name")(maintenance_name)
    _reason = field_validator("reason")(reason_text)


class Create(Definition):
    command_id: str
    _command = field_validator("command_id")(uuid_string)


class Test(Definition):
    alert_id: str
    _alert = field_validator("alert_id")(uuid_string)


class SavedTest(StrictModel):
    alert_id: str
    expected_revision: str
    _alert = field_validator("alert_id")(uuid_string)
    _revision = field_validator("expected_revision")(Command.revision)


class MetadataEdit(Command):
    kind: Literal["metadata"]
    name: str | None = Field(default=None, max_length=200)
    reason: str | None = Field(default=None, max_length=10000)

    @model_validator(mode="after")
    def content(self):
        if not self.model_fields_set.intersection({"name", "reason"}):
            raise ValueError("Supply a metadata change.")
        for field in ("name", "reason"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError("Explicit null is not a metadata value.")
        if self.name is not None:
            self.name = maintenance_name(self.name)
        if self.reason is not None:
            self.reason = reason_text(self.reason)
        return self


class TimezoneEdit(Command):
    kind: Literal["timezone"]
    timezone: str = Field(min_length=1, max_length=128)


class ScheduleEdit(Command):
    kind: Literal["schedule"]
    timezone: str | None = Field(default=None, min_length=1, max_length=128)
    start_local: str | None = None
    end_local: str | None = None
    start_occurrence: Literal["first", "second"] | None = None
    end_occurrence: Literal["first", "second"] | None = None
    cel: str | None = Field(default=None, min_length=1, max_length=16384)

    @model_validator(mode="after")
    def changed_endpoints(self):
        if not self.model_fields_set.intersection({"start_local", "end_local", "cel"}):
            raise ValueError("Supply explicit changed endpoints or CEL.")
        for name in ("timezone", "start_local", "end_local", "cel"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError("Explicit null is not a schedule change.")
        if self.start_occurrence is not None and self.start_local is None:
            raise ValueError("Occurrence requires its changed endpoint.")
        if self.end_occurrence is not None and self.end_local is None:
            raise ValueError("Occurrence requires its changed endpoint.")
        return self


Edit = Annotated[MetadataEdit | TimezoneEdit | ScheduleEdit, Field(discriminator="kind")]
