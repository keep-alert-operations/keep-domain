from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json

from appchi.cel.catalog import INDEX_FIELDS as FIELDS, storage_name
from appchi.cel.compiler import PROFILE, epoch_us, timestamp
from appchi.shared.errors import AppError, unavailable
from .text import TOKENIZER_PROFILE, max_query_token_bytes, source_tokens

SORTABLE = frozenset(
    (
        "application",
        "component",
        "node_name",
        "site",
        "operator",
        "severity",
        "status",
        "time_created",
        "first_received_at",
        "timestamp",
        "last_received_at",
        "occurrence_number",
        "opened_at",
        "resolved_at",
        "acknowledged",
        "assignee_id",
    )
)


def canonical(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def index_mapping() -> dict:
    properties = {}
    for name, spec in FIELDS.items():
        name = storage_name(name)
        if spec.kind == "bool":
            properties[name] = {"type": "boolean"}
        elif spec.kind in {"int", "time"}:
            properties[name] = {"type": "long"}
        elif name == "message":
            properties[name] = {"type": "wildcard"}
        else:
            properties[name] = {"type": "keyword", "ignore_above": spec.max_bytes}
        if spec.nullable:
            properties["missing_" + name] = {"type": "boolean"}
    properties.update(
        {
            "deleted": {"type": "boolean"},
            "projection_version": {"type": "long"},
            "content_digest": {"type": "keyword", "ignore_above": 64},
            "severity_clear_last": {"type": "boolean"},
            "severity_rank": {"type": "long"},
            "search_tokens": {"type": "keyword", "ignore_above": max_query_token_bytes()},
            "display": {"type": "object", "enabled": False},
        }
    )
    return {
        "dynamic": "strict",
        "_source": {"enabled": True},
        "_meta": {"cel_profile": PROFILE, "text_profile": TOKENIZER_PROFILE},
        "properties": properties,
    }


@dataclass(frozen=True)
class Projection:
    tenant_id: str
    seq: int
    alert_id: str
    version: int
    snapshot: dict
    # Authority readers may tokenize notes through a bounded server cursor.
    # This is an internal projection value, never a source-supplied field.
    tokens: tuple[str, ...] | None = None


def build_document(item: Projection) -> dict:
    if item.version < 1 or item.seq < 1:
        raise AppError("invalid_projection", "Projection versions and sequences must be positive")
    snapshot = item.snapshot
    if (
        str(snapshot.get("id", item.alert_id)) != item.alert_id
        or str(snapshot.get("tenant_id", item.tenant_id)) != item.tenant_id
    ):
        raise AppError(
            "invalid_projection", "Projection identity does not match its durable envelope"
        )
    deleted = snapshot.get("deleted") is True or snapshot.get("live") is False
    result = {
        "id": item.alert_id,
        "tenant_id": item.tenant_id,
        "projection_version": item.version,
        "deleted": deleted,
    }
    if deleted:
        # No source content, note text, display data or actor IDs survive here.
        return result
    display = {}
    for name, spec in FIELDS.items():
        if name == "timestamp":
            continue
        value = snapshot.get(
            name, snapshot.get("timestamp") if name == "last_received_at" else None
        )
        if value is None and not spec.nullable:
            if name == "incident_ids":
                value = []
            else:
                raise AppError("invalid_projection", f"Required searchable field missing: {name}")
        display[name] = value.isoformat() if isinstance(value, datetime) else value
        if spec.kind == "time" and value is not None:
            result[name] = epoch_us(value) if isinstance(value, datetime) else timestamp(value)
        elif (
            spec.kind == "int" and isinstance(value, str) and value.isascii() and value.isdecimal()
        ):
            # The authoritative JSON wire format represents counters as decimal
            # strings; the search mapping and typed CEL activation use int64.
            result[name] = int(value)
        else:
            result[name] = value
        if spec.nullable:
            result["missing_" + name] = value is None
    display["timestamp"] = display["last_received_at"]
    display["projection_version"] = item.version
    if "revision" in snapshot:
        display["revision"] = snapshot["revision"]
    notes = snapshot.get("notes", [])
    if not isinstance(notes, list) or any(not isinstance(note, str) for note in notes):
        raise AppError("invalid_projection", "Only current undeleted note strings may be projected")
    # Notes are searchable tokens; alert-owned authoritative note reads stay in PG.
    result["search_tokens"] = (
        list(item.tokens)
        if item.tokens is not None
        else source_tokens([snapshot["message"], snapshot.get("impact") or "", *notes])
    )
    result["severity_clear_last"] = snapshot["severity"] == "clear"
    result["severity_rank"] = {"critical": 0, "high": 1, "warning": 2, "clear": 3}[
        snapshot["severity"]
    ]
    # Source presentation strings are preserved independently of integer time fields.
    result["display"] = display
    result["content_digest"] = sha256(canonical(result)).hexdigest()
    return result


def assert_complete(response: dict):
    shards = response.get("_shards", {})
    if (
        response.get("timed_out")
        or response.get("terminated_early")
        or shards.get("failed", 0)
        or "failures" in shards
    ):
        raise unavailable("search_partial")


@dataclass(frozen=True)
class VisibilityProof:
    index_epoch: str
    covered: tuple[tuple[str, int, str, int], ...]
