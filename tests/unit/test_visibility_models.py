from uuid import UUID, uuid4

import pytest

from keep.ingestion.native import canonical
from keep.shared.errors import AppError
from keep.visibility.models import (
    ChangeView,
    RegisterView,
    decode_acknowledgements,
    decode_model,
)
from keep.visibility.limits import RegistryLimits
from keep.visibility.sampling import selected


def acknowledgement():
    return {
        "observation_id": str(uuid4()),
        "view_id": str(uuid4()),
        "view_epoch": "1",
        "resource": "alert_feed",
        "query_digest": "f" * 64,
        "outcome": "nonmatching",
        "observed": {"index_epoch": "test", "searchable_seq": "11", "view_generation": "9"},
    }


def test_ack_body_cardinality_bytes_and_duplicate_identity():
    body = {"observations": [acknowledgement() for _ in range(100)]}
    assert len(decode_acknowledgements(canonical(body)).observations) == 100
    body["observations"].append(acknowledgement())
    with pytest.raises(AppError, match="invalid_request"):
        decode_acknowledgements(canonical(body))
    item = acknowledgement()
    with pytest.raises(AppError, match="invalid_request"):
        decode_acknowledgements(canonical({"observations": [item, item]}))
    with pytest.raises(AppError, match="request_too_large"):
        decode_acknowledgements(b" " * 65537)
    with pytest.raises(AppError, match="duplicate_key"):
        decode_acknowledgements(b'{"observations":[],"observations":[]}')


@pytest.mark.parametrize(
    "path,value",
    [
        (("view_epoch",), 1),
        (("view_epoch",), "0"),
        (("view_epoch",), "01"),
        (("view_epoch",), "9223372036854775808"),
        (("query_digest",), "F" * 64),
        (("observation_id",), "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"),
        (("observed", "searchable_seq"), True),
        (("observed", "unissued_version"), "1"),
        (("outcome",), "hint_received"),
        (("rendered_at",), "2026-09-23T00:00:00Z"),
    ],
)
def test_ack_rejects_coercions_unknown_fields_and_browser_timing(path, value):
    item = acknowledgement()
    target = item
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(AppError, match="invalid_request"):
        decode_acknowledgements(canonical({"observations": [item]}))


def test_descriptor_and_revision_strictness():
    base = {
        "command_id": str(uuid4()),
        "tab_id": str(uuid4()),
        "view": {"surface": "alert_feed"},
        "state": "foreground",
    }
    assert decode_model(canonical(base), RegisterView).view.expression == "true"
    base["view"]["include_suppressed"] = "false"
    with pytest.raises(AppError, match="invalid_request"):
        decode_model(canonical(base), RegisterView)
    base["view"] = {"surface": "dashboard", "resource_id": str(uuid4()), "expression": "false"}
    with pytest.raises(AppError, match="invalid_request"):
        decode_model(canonical(base), RegisterView)
    with pytest.raises(AppError, match="invalid_request"):
        decode_model(
            canonical({"command_id": str(uuid4()), "expected_revision": "0", "state": "closed"}),
            ChangeView,
        )


@pytest.mark.parametrize("q", ["a" * 257, "text\nline", "text\u0000", "text\u200b", "???"])
def test_query_limit_and_plain_text_validation(q):
    body = {
        "command_id": str(uuid4()),
        "tab_id": str(uuid4()),
        "view": {"surface": "alert_feed", "q": q},
        "state": "foreground",
    }
    with pytest.raises(AppError):
        decode_model(canonical(body), RegisterView)


def test_sampling_independent_of_response_and_stable_across_retry():
    args = dict(
        view_id=UUID(int=1000),
        view_epoch=1,
        policy_epoch="test-policy",
        kind="incoming",
        qualification=False,
    )
    decisions = [selected(input_id=UUID(int=i), **args) for i in range(1, 10001)]
    assert 850 < sum(decisions) < 1150
    assert decisions == [selected(input_id=UUID(int=i), **args) for i in range(1, 10001)]
    for i in range(1, 100):
        assert selected(input_id=UUID(int=i), **{**args, "qualification": True})
        assert selected(input_id=UUID(int=i), **{**args, "kind": "maintenance_expiry"})
    with pytest.raises(ValueError):
        selected(input_id=UUID(int=1), **{**args, "qualification": "true"})
    assert decisions != [
        selected(input_id=UUID(int=i), **{**args, "view_epoch": 2}) for i in range(1, 10001)
    ]


def test_registry_requires_explicit_bounded_allocations():
    good = dict(
        lease_seconds=30,
        max_active_session_views=2,
        max_active_tenant_views=4,
        max_tenant_controls=100,
        max_descriptor_bytes=20000,
        max_request_bytes=65536,
    )
    assert RegistryLimits(**good).lease_seconds == 30
    for key, bad in (
        ("lease_seconds", True),
        ("max_tenant_controls", 0),
        ("max_request_bytes", 65537),
    ):
        with pytest.raises(ValueError):
            RegistryLimits(**{**good, key: bad})
