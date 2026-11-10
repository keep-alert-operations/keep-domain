from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4
import json

import pytest
from pydantic import ValidationError

from keep.events import received, changed
from keep.event_models import ReceivedEnvelope, ChangedEnvelope


def test_exact_decimal_counter_and_reference_integrity():
    tenant, item = uuid4(), uuid4()
    raw = received(
        tenant=tenant,
        item=item,
        order=9007199254740999,
        native_version="v2",
        payload={"message": "kept in PG"},
        at=datetime.now(UTC),
    )
    body = json.loads(raw)
    assert body["admission_order"] == "9007199254740999"
    assert "kept in PG" not in raw.decode()
    assert len(raw) < 8192
    for bad in (
        {**body, "admission_order": 1},
        {**body, "admission_order": "9223372036854775808"},
        {**body, "payload_ref": {**body["payload_ref"], "tenant_id": str(uuid4())}},
        {**body, "raw_json": "secret"},
    ):
        with pytest.raises(ValidationError):
            ReceivedEnvelope.model_validate(bad)


def test_retirement_reference_carries_no_source_content():
    tenant, alert = uuid4(), uuid4()
    now = datetime.now(UTC)
    raw = changed(
        tenant=tenant,
        alert=alert,
        seq=2,
        version=3,
        snapshot={"live": False},
        change_order=2,
        cause="retired",
        effective_at=now,
        recorded_at=now,
    )
    body = ChangedEnvelope.model_validate_json(raw)
    assert body.native_version is None and body.actor_id is None
    assert body.snapshot_ref.tenant_id == str(tenant)


def test_event_time_normalizes_an_explicit_non_utc_database_boundary():
    at = datetime(2026, 9, 22, 13, 30, tzinfo=timezone(timedelta(hours=3)))
    body = json.loads(
        received(tenant=uuid4(), item=uuid4(), order=1, native_version="v1", payload={}, at=at)
    )
    assert body["received_at"] == "2026-09-22T10:30:00.000000Z"
