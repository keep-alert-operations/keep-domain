"""Unconnected authority proof contracts; validation is never recovery approval.

Only IDs, counters, digests and typed effects leave these models. Snapshot
helpers accept explicit nonsecret projections locally and return digests only.
No producer, independent adapter, database or capability gate uses this module.
"""

from datetime import UTC, datetime
from hashlib import sha256
import json
from typing import Annotated, Literal
from uuid import UUID, uuid5

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_serializer,
    model_validator,
)


def _identifier(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError("Canonical UUID text required")
    return value


def _counter(value):
    if (
        type(value) is not str
        or not value.isascii()
        or not value.isdecimal()
        or len(value) > 19
        or value != str(int(value))
        or int(value) > 2**63 - 1
    ):
        raise ValueError("Canonical decimal bigint text required")
    return value


Identifier = Annotated[str, BeforeValidator(_identifier)]
Counter = Annotated[str, BeforeValidator(_counter)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Lifecycle = Literal["setup_pending", "ready", "deleted"]
KeyState = Literal["prepared", "current", "retiring", "revoked", "expired"]
Family = Literal["permission", "operator", "credential"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _digest(value):
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    ).hexdigest()


class PermissionEffect(Strict):
    kind: Literal["permissions_changed"]


class OperatorEffect(Strict):
    kind: Literal["operator_lifecycle"]
    before: Literal["absent", "setup_pending", "ready"]
    after: Lifecycle

    @model_validator(mode="after")
    def transition(self):
        allowed = {
            "absent": {"setup_pending"},
            "setup_pending": {"ready", "deleted"},
            "ready": {"deleted"},
        }
        if self.after not in allowed[self.before]:
            raise ValueError("Invalid operator lifecycle transition")
        return self


class CredentialEffect(Strict):
    kind: Literal["credential_lifecycle"]
    operator_id: Identifier
    before: Literal["absent", "prepared", "current", "retiring"]
    after: KeyState

    @model_validator(mode="after")
    def transition(self):
        allowed = {
            "absent": {"prepared"},
            "prepared": {"current", "revoked"},
            "current": {"retiring", "revoked"},
            "retiring": {"expired", "revoked"},
        }
        if self.after not in allowed[self.before]:
            raise ValueError("Invalid credential lifecycle transition")
        return self


Effect = Annotated[
    PermissionEffect | OperatorEffect | CredentialEffect, Field(discriminator="kind")
]


class AuthorityAttempt(Strict):
    """One immutable transition; later publishers must also enforce sequence history."""

    version: Literal["keep-authority-attempt-v1"]
    attempt_id: Identifier
    producer_epoch: Identifier
    producer_version: Literal["keep-authority-producer-v1"]
    tenant_id: Identifier
    resource_id: Identifier
    base_revision: Counter
    after_revision: Counter
    before_digest: Digest
    after_digest: Digest
    effect: Effect

    @model_validator(mode="after")
    def binding(self):
        if int(self.after_revision) != int(self.base_revision) + 1:
            raise ValueError("After revision must immediately follow base revision")
        if self.before_digest == self.after_digest:
            raise ValueError("No-op state cannot produce an authority transition")
        if isinstance(self.effect, PermissionEffect) and self.resource_id != self.tenant_id:
            raise ValueError("Permission authority is scoped to its tenant identity")
        if (
            isinstance(self.effect, CredentialEffect)
            and self.resource_id == self.effect.operator_id
        ):
            raise ValueError("Credential and operator identities must differ")
        if isinstance(self.effect, (OperatorEffect, CredentialEffect)):
            if (self.effect.before == "absent") != (self.base_revision == "0"):
                raise ValueError("Only creation may start at revision zero")
        return self


def phase_id(attempt_id, state):
    _identifier(attempt_id)
    if state not in ("intent", "final", "cancel"):
        raise ValueError("Unknown evidence phase")
    return str(uuid5(UUID(attempt_id), "keep-authority-evidence-v1:" + state))


class AuthorityRecord(Strict):
    version: Literal["keep-authority-evidence-v1"]
    id: Identifier
    state: Literal["intent", "final", "cancel"]
    attempt: AuthorityAttempt
    digest: Digest

    @model_validator(mode="after")
    def binding(self):
        if self.id != phase_id(self.attempt.attempt_id, self.state):
            raise ValueError("Evidence ID does not bind its attempt and phase")
        if self.digest != _digest(self.model_dump(mode="json", exclude={"digest"})):
            raise ValueError("Evidence digest does not bind its complete descriptor")
        return self


def authority_record(attempt: AuthorityAttempt, state: Literal["intent", "final", "cancel"]):
    if not isinstance(attempt, AuthorityAttempt):
        raise TypeError("Validated authority attempt required")
    value = {
        "version": "keep-authority-evidence-v1",
        "id": phase_id(attempt.attempt_id, state),
        "state": state,
        "attempt": attempt.model_dump(mode="json"),
    }
    return AuthorityRecord.model_validate({**value, "digest": _digest(value)})


class Baseline(Strict):
    kind: Literal["baseline"]
    heads_count: Counter
    heads_digest: Digest


class Opened(Strict):
    kind: Literal["opened"]
    baseline_id: Identifier
    baseline_digest: Digest


class Closed(Strict):
    kind: Literal["closed"]
    baseline_id: Identifier
    baseline_digest: Digest
    open_id: Identifier
    open_digest: Digest
    changes_count: Counter
    changes_digest: Digest


class CoverageDescriptor(Strict):
    version: Literal["keep-authority-coverage-descriptor-v1"]
    producer_epoch: Identifier
    producer_version: Literal["keep-authority-producer-v1"]
    tenant_id: Identifier
    families: Annotated[tuple[Family, ...], Field(min_length=1, max_length=3)]
    marker: Annotated[Baseline | Opened | Closed, Field(discriminator="kind")]

    @model_validator(mode="after")
    def binding(self):
        if tuple(sorted(set(self.families))) != self.families:
            raise ValueError("Coverage families must be unique and canonically ordered")
        if isinstance(self.marker, Closed) and self.marker.open_id != coverage_id(
            self.producer_epoch, "opened"
        ):
            raise ValueError("Close must reference this producer epoch's open record")
        return self


def coverage_id(epoch, kind):
    _identifier(epoch)
    if kind not in ("baseline", "opened", "closed"):
        raise ValueError("Unknown coverage marker")
    return str(uuid5(UUID(epoch), "keep-authority-coverage-v1:" + kind))


class CoverageRecord(Strict):
    version: Literal["keep-authority-coverage-v1"]
    id: Identifier
    descriptor: CoverageDescriptor
    digest: Digest

    @model_validator(mode="after")
    def binding(self):
        descriptor = self.descriptor
        if self.id != coverage_id(descriptor.producer_epoch, descriptor.marker.kind):
            raise ValueError("Coverage ID does not bind its epoch and marker")
        if (
            isinstance(descriptor.marker, (Opened, Closed))
            and descriptor.marker.baseline_id == self.id
        ):
            raise ValueError("Coverage record cannot be its own baseline")
        if self.digest != _digest(self.model_dump(mode="json", exclude={"digest"})):
            raise ValueError("Coverage digest does not bind its complete descriptor")
        return self


def coverage_record(descriptor: CoverageDescriptor):
    if not isinstance(descriptor, CoverageDescriptor):
        raise TypeError("Validated coverage descriptor required")
    value = {
        "version": "keep-authority-coverage-v1",
        "id": coverage_id(descriptor.producer_epoch, descriptor.marker.kind),
        "descriptor": descriptor.model_dump(mode="json"),
    }
    # JSON round-trip preserves strict tuple wire semantics without accepting
    # Python list-to-tuple coercion in model_validate.
    return CoverageRecord.model_validate_json(json.dumps({**value, "digest": _digest(value)}))


class GrantState(Strict):
    principal_id: Identifier
    directory_source: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    role: Literal["view", "edit", "admin"]


class PermissionState(Strict):
    tenant_id: Identifier
    authority_revision: Counter
    grants: tuple[GrantState, ...]

    @model_validator(mode="after")
    def identities(self):
        if len({grant.principal_id for grant in self.grants}) != len(self.grants) or len(
            {(grant.directory_source, grant.object_id) for grant in self.grants}
        ) != len(self.grants):
            raise ValueError("Duplicate permission principal identity")
        return self


def permission_state_digest(state):
    state = PermissionState.model_validate(state)
    value = state.model_dump(mode="json")
    value["grants"].sort(key=lambda item: item["principal_id"])
    return _digest({"version": "keep-permission-state-v1", "state": value})


def _instant(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("An aware database datetime is required")
    return value.astimezone(UTC)


Instant = Annotated[datetime, BeforeValidator(_instant)]


class CredentialState(Strict):
    id: Identifier
    operator_id: Identifier
    state: KeyState
    activated_at: Instant | None
    expires_at: Instant | None
    revoked_at: Instant | None
    kong_consumer_id: Identifier | None
    kong_credential_id: Identifier | None
    has_ciphertext: bool

    @field_serializer("activated_at", "expires_at", "revoked_at")
    def instants(self, value):
        return (
            value.isoformat(timespec="microseconds").replace("+00:00", "Z")
            if value is not None
            else None
        )

    @model_validator(mode="after")
    def lifecycle(self):
        if self.state in ("revoked", "expired") and self.has_ciphertext:
            raise ValueError("Denied credentials cannot retain ciphertext")
        if self.state in ("prepared", "current", "retiring") and not self.has_ciphertext:
            raise ValueError("Live credential material is missing")
        if self.state == "prepared" and any(
            value is not None for value in (self.activated_at, self.expires_at, self.revoked_at)
        ):
            raise ValueError("Prepared credential cannot have lifecycle instants")
        if self.state in ("current", "retiring", "expired") and self.activated_at is None:
            raise ValueError("Activated lifecycle requires original activation instant")
        if self.state in ("retiring", "expired") and (
            self.expires_at is None or self.expires_at <= self.activated_at
        ):
            raise ValueError("Retiring lifecycle requires its original later deadline")
        if self.state == "current" and self.expires_at is not None:
            raise ValueError("Current credentials have no expiry deadline")
        if self.expires_at is not None and (
            self.activated_at is None or self.expires_at <= self.activated_at
        ):
            raise ValueError("Expiry must preserve a deadline after original activation")
        if (self.state == "revoked") != (self.revoked_at is not None):
            raise ValueError("Revocation state and instant differ")
        if (self.kong_consumer_id is None) != (self.kong_credential_id is None):
            raise ValueError("Kong identity binding is incomplete")
        return self


class OperatorState(Strict):
    tenant_id: Identifier
    operator_id: Identifier
    revision: Counter
    generation: Counter
    lifecycle: Lifecycle
    deletion_pending: bool
    credentials: tuple[CredentialState, ...]

    @model_validator(mode="after")
    def scope(self):
        if self.revision == "0" or self.generation == "0":
            raise ValueError("Existing operators require positive revisions and generations")
        if len({key.id for key in self.credentials}) != len(self.credentials):
            raise ValueError("Duplicate credential identity")
        if any(
            key.operator_id != self.operator_id or key.id == self.operator_id
            for key in self.credentials
        ):
            raise ValueError("Credential parent differs from operator snapshot")
        if any(
            sum(key.state == state for key in self.credentials) > 1
            for state in ("prepared", "current", "retiring")
        ):
            raise ValueError("Duplicate live credential state")
        if self.lifecycle == "deleted" and any(
            key.state not in ("revoked", "expired") for key in self.credentials
        ):
            raise ValueError("Deleted operator cannot retain usable credentials")
        return self


def operator_state_digest(state):
    state = OperatorState.model_validate(state)
    value = state.model_dump(mode="json")
    value["credentials"].sort(key=lambda item: item["id"])
    return _digest({"version": "keep-operator-authority-state-v1", "state": value})
