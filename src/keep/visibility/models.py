"""Strict wire contracts. An acknowledgement model is not an accepted proof."""

from typing import Annotated, Literal
import unicodedata
from uuid import UUID

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from keep.ingestion.native import parse_json
from keep.shared.errors import AppError
from keep.search.text import query_tokens


def _uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Canonical UUID text required")
    return value


def _counter(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("Canonical decimal counter required")
    if value != str(int(value)) or int(value) > 2**63 - 1:
        raise ValueError("Counter outside PostgreSQL bigint range")
    return value


Identifier = Annotated[str, BeforeValidator(_uuid)]
Counter = Annotated[str, Field(max_length=19), BeforeValidator(_counter)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ViewDescriptor(StrictModel):
    """Client intent only; resource existence, CEL and query eligibility are unproven."""

    surface: Literal["alert_feed", "alert_detail", "preset", "dashboard"]
    resource_id: Identifier | None = None
    expression: str = Field(default="true", min_length=1, max_length=16384)
    q: str = Field(default="", max_length=256)
    include_suppressed: bool = False
    sort: str = Field(default="timestamp", min_length=1, max_length=64)
    direction: Literal["asc", "desc"] = "desc"
    page_mode: Literal["current", "frozen"] = "current"

    @field_validator("q")
    @classmethod
    def plain_text_query(cls, value):
        if any(unicodedata.category(char).startswith("C") for char in value):
            raise ValueError("Query controls and surrogate characters are not accepted")
        query_tokens(value)
        return value

    @model_validator(mode="after")
    def shape(self):
        if len(self.expression.encode("utf-8")) > 16384:
            raise ValueError("CEL source exceeds the native byte limit")
        if (self.surface == "alert_feed") != (self.resource_id is None):
            raise ValueError("Only a feed omits resource_id")
        if self.surface != "alert_feed" and (
            self.expression != "true"
            or self.q
            or self.include_suppressed
            or self.sort != "timestamp"
            or self.direction != "desc"
        ):
            raise ValueError("Saved resource queries must be resolved by the server")
        return self


class RegisterView(StrictModel):
    command_id: Identifier
    tab_id: Identifier
    view: ViewDescriptor
    state: Literal["foreground", "background"]


class ChangeView(StrictModel):
    command_id: Identifier
    expected_revision: Counter
    state: Literal["foreground", "background", "closed"]
    view: ViewDescriptor | None = None

    @model_validator(mode="after")
    def revision(self):
        if self.expected_revision == "0":
            raise ValueError("A positive revision is required")
        if self.state == "closed" and self.view is not None:
            raise ValueError("Close cannot replace the query")
        return self


class ResourceVersion(StrictModel):
    resource_id: Identifier
    revision: Counter
    projection_version: Counter | None = None


class ObservedBounds(StrictModel):
    index_epoch: str = Field(min_length=1, max_length=256)
    searchable_seq: Counter
    view_generation: Counter
    maintenance_generation: Counter | None = None
    resources: list[ResourceVersion] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_resources(self):
        if len({r.resource_id for r in self.resources}) != len(self.resources):
            raise ValueError("Duplicate resource version")
        return self


class RenderAcknowledgement(StrictModel):
    observation_id: Identifier
    view_id: Identifier
    view_epoch: Counter
    resource: Literal["alert_feed", "alert_detail", "preset", "dashboard"]
    resource_id: Identifier | None = None
    query_digest: Digest
    outcome: Literal["matching", "nonmatching", "counts"]
    observed: ObservedBounds

    @model_validator(mode="after")
    def scope(self):
        if self.view_epoch == "0":
            raise ValueError("A positive view epoch is required")
        if (self.resource == "alert_feed") != (self.resource_id is None):
            raise ValueError("Invalid resource scope")
        return self


class AcknowledgementBatch(StrictModel):
    observations: list[RenderAcknowledgement] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique_observations(self):
        ids = [o.observation_id for o in self.observations]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate observation in batch")
        return self


def decode_model(raw: bytes, model, *, maximum_bytes: int = 65536):
    if len(raw) > maximum_bytes:
        raise AppError("request_too_large", "Request exceeds its byte allocation.", 413)
    try:
        return model.model_validate(parse_json(raw))
    except ValidationError:
        raise AppError(
            "invalid_request", "Request does not match the required schema.", 422
        ) from None


def decode_acknowledgements(raw: bytes) -> AcknowledgementBatch:
    """Structural validation only. Never mark an observation successful here."""
    return decode_model(raw, AcknowledgementBatch)
