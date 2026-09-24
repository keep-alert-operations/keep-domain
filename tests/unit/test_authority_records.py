"""Pure descriptor checks: these tests do not qualify protected publication."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
import json
from uuid import UUID

import pytest
from pydantic import ValidationError

from appchi.recovery.authority_records import (
    AuthorityAttempt,
    AuthorityRecord,
    CoverageDescriptor,
    CoverageRecord,
    CredentialState,
    OperatorState,
    PermissionState,
    authority_record,
    coverage_id,
    coverage_record,
    operator_state_digest,
    permission_state_digest,
    phase_id,
)


TENANT = "10000000-0000-4000-8000-000000000001"
OPERATOR = "20000000-0000-4000-8000-000000000002"
KEY = "30000000-0000-4000-8000-000000000003"
OTHER = "abcdef00-0000-4000-8000-000000000004"
EPOCH = "50000000-0000-4000-8000-000000000005"
ATTEMPT = "60000000-0000-4000-8000-000000000006"
WHEN = datetime(2026, 9, 23, 12, 0, 0, 123456, tzinfo=UTC)


def attempt(**changes):
    return (
        dict(
            version="appchi-authority-attempt-v1",
            attempt_id=ATTEMPT,
            producer_epoch=EPOCH,
            producer_version="appchi-authority-producer-v1",
            tenant_id=TENANT,
            resource_id=TENANT,
            base_revision="1",
            after_revision="2",
            before_digest="a" * 64,
            after_digest="b" * 64,
            effect={"kind": "permissions_changed"},
        )
        | changes
    )


def credential(**changes):
    return (
        dict(
            id=KEY,
            operator_id=OPERATOR,
            state="current",
            activated_at=WHEN,
            expires_at=None,
            revoked_at=None,
            kong_consumer_id=OPERATOR,
            kong_credential_id=OTHER,
            has_ciphertext=True,
        )
        | changes
    )


def operator(**changes):
    return (
        dict(
            tenant_id=TENANT,
            operator_id=OPERATOR,
            revision="2",
            generation="1",
            lifecycle="ready",
            deletion_pending=False,
            credentials=(credential(),),
        )
        | changes
    )


def permission(**changes):
    return (
        dict(
            tenant_id=TENANT,
            authority_revision="2",
            grants=(
                dict(
                    principal_id=OPERATOR,
                    directory_source="company",
                    object_id="immutable-1",
                    role="view",
                ),
                dict(
                    principal_id=OTHER,
                    directory_source="company",
                    object_id="immutable-2",
                    role="admin",
                ),
            ),
        )
        | changes
    )


def coverage(**changes):
    return (
        dict(
            version="appchi-authority-coverage-descriptor-v1",
            producer_epoch=EPOCH,
            producer_version="appchi-authority-producer-v1",
            tenant_id=TENANT,
            families=("credential", "operator", "permission"),
            marker={"kind": "baseline", "heads_count": "0", "heads_digest": "a" * 64},
        )
        | changes
    )


@pytest.mark.parametrize(
    "value", [UUID(OTHER), OTHER.upper(), "{" + OTHER + "}", " " + OTHER, None, 1]
)
def test_canonical_uuid_required(value):
    with pytest.raises(ValidationError):
        AuthorityAttempt.model_validate(attempt(attempt_id=value))


@pytest.mark.parametrize(
    "value", [1, True, 1.0, None, "01", "-1", "1.0", "１", " 1", "", str(2**63)]
)
def test_canonical_counter_required(value):
    with pytest.raises(ValidationError):
        AuthorityAttempt.model_validate(attempt(base_revision=value))


@pytest.mark.parametrize(
    "changes",
    [
        {"version": "v2"},
        {"after_revision": "3"},
        {"after_digest": "a" * 64},
        {"before_digest": "A" * 64},
        {"before_digest": "a" * 64 + "\n"},
        {"resource_id": OPERATOR},
        {"effect": None},
        {"effect": {"kind": "unknown"}},
        {"effect": {"kind": "permissions_changed", "role": "admin"}},
        {"grants": []},
        {"username": "person"},
        {"configuration": {}},
        {"key": "secret"},
    ],
)
def test_attempt_rejects_unknown_null_content_and_unbound_changes(changes):
    with pytest.raises(ValidationError):
        AuthorityAttempt.model_validate(attempt(**changes))


def test_attempt_phases_bind_full_descriptor_and_round_trip():
    value = AuthorityAttempt.model_validate(attempt())
    records = [authority_record(value, phase) for phase in ("intent", "final", "cancel")]
    assert len({record.id for record in records}) == 3
    assert len({record.digest for record in records}) == 3
    for record in records:
        assert AuthorityRecord.model_validate_json(record.model_dump_json()) == record
        assert record.id == phase_id(ATTEMPT, record.state)
    for field, replacement in [
        ("attempt_id", OTHER),
        ("producer_epoch", OTHER),
        ("before_digest", "c" * 64),
        ("after_digest", "c" * 64),
    ]:
        changed = records[0].model_dump(mode="json")
        changed["attempt"][field] = replacement
        with pytest.raises(ValidationError):
            AuthorityRecord.model_validate(changed)
    for field, replacement in [("state", "final"), ("id", OTHER), ("digest", "c" * 64)]:
        with pytest.raises(ValidationError):
            AuthorityRecord.model_validate(
                records[0].model_dump(mode="json") | {field: replacement}
            )


def test_credential_attempt_binds_parent_and_creation_revision():
    effect = dict(
        kind="credential_lifecycle", operator_id=OPERATOR, before="absent", after="prepared"
    )
    value = attempt(resource_id=KEY, base_revision="0", after_revision="1", effect=effect)
    AuthorityAttempt.model_validate(value)
    for change in [
        {"operator_id": KEY},
        {"operator_id": None},
        {"before": "revoked"},
        {"before": "current", "after": "prepared"},
        {"before": "prepared"},
    ]:
        with pytest.raises(ValidationError):
            AuthorityAttempt.model_validate(value | {"effect": effect | change})
    with pytest.raises(ValidationError):
        AuthorityAttempt.model_validate(value | {"base_revision": "1", "after_revision": "2"})
    with pytest.raises(ValidationError):
        AuthorityAttempt.model_validate(
            value | {"effect": {k: v for k, v in effect.items() if k != "operator_id"}}
        )
    record = authority_record(AuthorityAttempt.model_validate(value), "intent")
    changed = record.model_dump(mode="json")
    changed["attempt"]["effect"]["operator_id"] = OTHER
    with pytest.raises(ValidationError):
        AuthorityRecord.model_validate(changed)


def test_permission_digest_exact_identity_role_revision_and_order():
    original = permission()
    digest = permission_state_digest(original)
    assert permission_state_digest(permission(grants=original["grants"][::-1])) == digest
    for field, value in [
        ("role", "edit"),
        ("object_id", "IMMUTABLE-1"),
        ("directory_source", "Company"),
        ("principal_id", KEY),
    ]:
        changed = deepcopy(original)
        changed["grants"][0][field] = value
        assert permission_state_digest(changed) != digest
    assert permission_state_digest(permission(authority_revision="3")) != digest
    assert permission_state_digest(permission(tenant_id=OTHER)) != digest
    first = original["grants"][0]
    assert permission_state_digest(
        permission(grants=(first | {"object_id": "é"},))
    ) != permission_state_digest(permission(grants=(first | {"object_id": "e\u0301"},)))


@pytest.mark.parametrize("change", [{"principal_id": OPERATOR}, {"object_id": "immutable-1"}])
def test_permission_duplicate_binding_rejected(change):
    value = permission()
    value["grants"][1].update(change)
    with pytest.raises(ValidationError):
        permission_state_digest(value)


def test_snapshot_inputs_require_explicit_projection():
    with pytest.raises(ValidationError):
        PermissionState.model_validate(permission() | {"name": "tenant name"})
    for field in ("ciphertext", "verifier_digest", "secret", "wrapping_key_version"):
        with pytest.raises(ValidationError):
            CredentialState.model_validate(credential() | {field: "must not be accepted"})
    with pytest.raises(ValidationError):
        OperatorState.model_validate(operator(deletion_pending=0))


def test_operator_digest_exact_lifecycle_instants_and_order():
    retired = credential(
        id=ATTEMPT, state="expired", expires_at=WHEN + timedelta(days=1), has_ciphertext=False
    )
    original = operator(credentials=(credential(), retired))
    digest = operator_state_digest(original)
    assert operator_state_digest(operator(credentials=original["credentials"][::-1])) == digest
    shifted = credential(activated_at=WHEN.astimezone(timezone(timedelta(hours=3))))
    assert operator_state_digest(operator(credentials=(shifted, retired))) == digest
    for field, value in [
        ("generation", "2"),
        ("revision", "3"),
        ("deletion_pending", True),
        ("lifecycle", "setup_pending"),
        ("tenant_id", OTHER),
    ]:
        assert operator_state_digest(original | {field: value}) != digest
    for change in [
        {"expires_at": retired["expires_at"] + timedelta(microseconds=1)},
        {"kong_credential_id": EPOCH},
        {"activated_at": WHEN + timedelta(microseconds=1)},
    ]:
        assert (
            operator_state_digest(operator(credentials=(credential(), retired | change))) != digest
        )
    serialized = OperatorState.model_validate(original).model_dump(mode="json")
    assert serialized["credentials"][0]["activated_at"] == "2026-09-23T12:00:00.123456Z"


@pytest.mark.parametrize(
    "change",
    [
        {"activated_at": WHEN.replace(tzinfo=None)},
        {"activated_at": WHEN.isoformat()},
        {"activated_at": None},
        {"state": "retiring"},
        {"expires_at": WHEN},
        {"state": "revoked", "revoked_at": WHEN},
        {"has_ciphertext": False},
        {"kong_credential_id": None},
        {"has_ciphertext": 1},
        {"state": "prepared"},
        {"revoked_at": WHEN},
    ],
)
def test_contradictory_credential_snapshot_rejected(change):
    with pytest.raises(ValidationError):
        CredentialState.model_validate(credential(**change))


def test_revocation_preserves_original_instants_and_erasure():
    denied = credential(
        state="revoked",
        revoked_at=WHEN + timedelta(hours=1),
        expires_at=WHEN + timedelta(days=1),
        has_ciphertext=False,
    )
    CredentialState.model_validate(denied)
    CredentialState.model_validate(denied | {"activated_at": None, "expires_at": None})
    with pytest.raises(ValidationError):
        CredentialState.model_validate(denied | {"activated_at": None})
    OperatorState.model_validate(operator(lifecycle="deleted", credentials=(denied,)))


@pytest.mark.parametrize(
    "changes",
    [
        {"credentials": (credential(), credential())},
        {"credentials": (credential(), credential(id=ATTEMPT))},
        {"credentials": (credential(operator_id=OTHER),)},
        {"credentials": (credential(id=OPERATOR),)},
        {"lifecycle": "deleted"},
        {"revision": "0"},
        {"generation": "0"},
    ],
)
def test_operator_snapshot_invariants(changes):
    with pytest.raises(ValidationError):
        operator_state_digest(operator(**changes))


def test_coverage_roundtrip_binds_scope_and_closed_tail():
    baseline = coverage_record(CoverageDescriptor.model_validate(coverage()))
    opening = dict(kind="opened", baseline_id=baseline.id, baseline_digest=baseline.digest)
    opened = coverage_record(CoverageDescriptor.model_validate(coverage(marker=opening)))
    close = dict(
        kind="closed",
        baseline_id=baseline.id,
        baseline_digest=baseline.digest,
        open_id=opened.id,
        open_digest=opened.digest,
        changes_count="1",
        changes_digest="b" * 64,
    )
    closed = coverage_record(CoverageDescriptor.model_validate(coverage(marker=close)))
    assert len({baseline.id, opened.id, closed.id}) == 3
    for record in (baseline, opened, closed):
        assert CoverageRecord.model_validate_json(record.model_dump_json()) == record
        assert record.id == coverage_id(EPOCH, record.descriptor.marker.kind)
    for change in [
        {"open_id": OTHER},
        {"baseline_id": None},
        {"changes_count": 1},
        {"complete": True},
    ]:
        with pytest.raises(ValidationError):
            CoverageDescriptor.model_validate(coverage(marker=close | change))
    for path, value in [("tenant_id", OTHER), ("families", ["permission"])]:
        changed = closed.model_dump(mode="json")
        changed["descriptor"][path] = value
        with pytest.raises(ValidationError):
            CoverageRecord.model_validate_json(json.dumps(changed))
    changed = closed.model_dump(mode="json")
    changed["descriptor"]["marker"]["changes_count"] = "2"
    with pytest.raises(ValidationError):
        CoverageRecord.model_validate_json(json.dumps(changed))


@pytest.mark.parametrize(
    "families",
    [
        (),
        ("operator", "credential"),
        ("permission", "permission"),
        ("unknown",),
        ["permission"],
        None,
    ],
)
def test_coverage_requires_canonical_family_set(families):
    with pytest.raises(ValidationError):
        CoverageDescriptor.model_validate(coverage(families=families))


def test_coverage_shape_does_not_claim_external_establishment():
    # Empty inventories and arbitrary digests may be well-shaped. A future
    # collector must verify actual inventory, durability and producer history.
    record = coverage_record(CoverageDescriptor.model_validate(coverage()))
    assert record.descriptor.marker.heads_count == "0"
    assert "ready" not in record.model_dump_json()
    with pytest.raises(ValidationError):
        CoverageDescriptor.model_validate(coverage(marker={"kind": "opened"}))
    with pytest.raises(ValidationError):
        CoverageDescriptor.model_validate(coverage() | {"verified": True})
