"""Immutable reference envelopes. Counters are decimal strings on the wire."""

from hashlib import sha256
from uuid import uuid4
from appchi.ingestion.native import canonical
from appchi.serialization import wire
from appchi.event_models import ChangedEnvelope, ReceivedEnvelope


def changed(
    *,
    tenant,
    alert,
    seq,
    version,
    snapshot,
    change_order,
    cause,
    effective_at,
    recorded_at,
    actor=None,
    original_order=None,
):
    body = {
        "schema_version": 1,
        "event_id": str(uuid4()),
        "kind": "alerts.changed",
        "tenant_id": str(tenant),
        "alert_id": str(alert),
        "projection_seq": str(seq),
        "projection_version": str(version),
        "change_order": str(change_order),
        "original_admission_order": str(original_order) if original_order is not None else None,
        "native_version": snapshot.get("schema_version"),
        "actor_id": str(actor) if actor else None,
        "cause": cause,
        "effective_at": wire(effective_at),
        "recorded_at": wire(recorded_at),
        "snapshot_ref": {"tenant_id": str(tenant), "seq": str(seq)},
        "snapshot_digest": sha256(canonical(snapshot)).hexdigest(),
    }
    encoded = canonical(ChangedEnvelope.model_validate(body).model_dump())
    if len(encoded) >= 8192:
        raise ValueError("Reference event exceeds transport envelope bound")
    return encoded


def received(*, tenant, item, order, native_version, payload, at):
    body = {
        "schema_version": 1,
        "event_id": str(item),
        "kind": "alerts.received",
        "tenant_id": str(tenant),
        "admission_order": str(order),
        "native_version": native_version,
        "actor_id": None,
        "cause": "source",
        "received_at": wire(at),
        "effective_at": wire(at),
        "recorded_at": wire(at),
        "payload_ref": {"tenant_id": str(tenant), "item_id": str(item)},
        "payload_digest": sha256(canonical(payload)).hexdigest(),
    }
    return canonical(ReceivedEnvelope.model_validate(body).model_dump())
