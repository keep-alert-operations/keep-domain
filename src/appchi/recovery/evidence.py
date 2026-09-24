"""Minimal recovery evidence. No content or credentials enter this interface."""

from dataclasses import asdict, dataclass
from typing import Callable, Literal, Protocol, get_args, get_type_hints
from urllib.parse import urlsplit
import re
from uuid import UUID
import hashlib
import asyncio
import json
import math
import time
import httpx

from appchi.shared.errors import unavailable


@dataclass(frozen=True)
class Evidence:
    id: str
    tenant_id: str
    resource_kind: Literal[
        "alert",
        "incident",
        "preset",
        "dashboard",
        "maintenance",
        "correlation",
        "credential",
        "permission",
        "command",
        "audit",
    ]
    resource_id: str
    revision: int
    state: Literal["intent", "final", "cancel"]
    digest: str

    def __post_init__(self):
        for value in (self.id, self.tenant_id, self.resource_id):
            if str(UUID(value)) != value:
                raise ValueError("Canonical UUID required")
        if (
            type(self.revision) is not int
            or not 0 <= self.revision <= 2**63 - 1
            or not isinstance(self.digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", self.digest)
            or self.resource_kind not in get_args(get_type_hints(Evidence)["resource_kind"])
            or self.state not in {"intent", "final", "cancel"}
        ):
            raise ValueError("Invalid minimal evidence")


@dataclass(frozen=True)
class DurableAck:
    evidence_id: str
    namespace: str
    checkpoint: str
    digest: str


class EvidenceStore(Protocol):
    def append(self, evidence: Evidence) -> DurableAck: ...
    def checkpoint(self, after: str | None) -> tuple[list[Evidence], str]: ...


PAGED_CHECKPOINT_VERSION = "appchi-evidence-checkpoint-v2"
CHECKPOINT_MAX_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class CheckpointPage:
    namespace: str
    after: str | None
    checkpoint: str
    request_cursor: str | None
    total_records: int
    records: tuple[Evidence, ...]
    next_cursor: str | None
    complete: bool
    page_digest: str


@dataclass(frozen=True)
class CheckpointCollection:
    namespace: str
    after: str | None
    checkpoint: str
    pages: int
    records: int
    binding_digest: str


class PagedEvidenceStore(Protocol):
    binding: "EvidenceBinding"

    def checkpoint_page(
        self,
        *,
        after: str | None = None,
        snapshot_checkpoint: str | None = None,
        cursor: str | None = None,
        page_size: int = 1000,
        timeout_seconds: float = 5,
    ) -> CheckpointPage: ...


def _token(value, *, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise ValueError("Bounded opaque token required")


def _decimal(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        raise ValueError("Canonical decimal string required")
    result = int(value)
    if result > 2**63 - 1:
        raise ValueError("Counter outside supported range")
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result


def checkpoint_page_digest(page):
    """Canonical v2 digest covers the full response except page_digest itself."""
    return hashlib.sha256(
        json.dumps(
            {key: value for key, value in page.items() if key != "page_digest"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class EvidenceBinding:
    origin: str
    append_path: str
    checkpoint_path: str
    namespace: str
    independence_evidence: str
    durability_evidence: str
    ca_file: str | None = None
    paged_checkpoint_path: str | None = None
    paged_checkpoint_version: Literal["appchi-evidence-checkpoint-v2"] | None = None

    def __post_init__(self):
        _token(self.namespace)
        parsed = urlsplit(self.origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or not self.namespace
            or not self.independence_evidence
            or not self.durability_evidence
        ):
            raise ValueError("Verified independent HTTPS evidence binding required")
        if (self.paged_checkpoint_path is None) != (self.paged_checkpoint_version is None):
            raise ValueError("Explicit paged checkpoint path and version required together")
        if self.paged_checkpoint_version not in (None, PAGED_CHECKPOINT_VERSION):
            raise ValueError("Unsupported paged checkpoint version")
        for path in (self.append_path, self.checkpoint_path, self.paged_checkpoint_path):
            if path is None:
                continue
            if (
                not path.startswith("/")
                or path.startswith("//")
                or any(part in path for part in ("://", "..", "?", "#", "\\"))
            ):
                raise ValueError("Relative service path required")


def checkpoint_binding_digest(binding: EvidenceBinding):
    """Pin nonsecret connection/qualification metadata, never a bearer credential."""
    return hashlib.sha256(
        json.dumps(
            asdict(binding), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


class HttpEvidenceStore:
    def __init__(self, binding: EvidenceBinding, credential: str, *, checkpoint_transport=None):
        self.binding = binding
        self.checkpoint_transport = checkpoint_transport
        self.client = httpx.Client(
            base_url=binding.origin,
            verify=binding.ca_file or True,
            timeout=5,
            follow_redirects=False,
            headers={"Authorization": "Bearer " + credential},
        )

    def append(self, evidence):
        body = {
            **asdict(evidence),
            "revision": str(evidence.revision),
            "namespace": self.binding.namespace,
        }
        try:
            response = self.client.post(
                self.binding.append_path, json=body, headers={"Idempotency-Key": evidence.id}
            )
            response.raise_for_status()
            ack = response.json()
            if (
                ack.get("evidence_id") != evidence.id
                or ack.get("digest") != evidence.digest
                or ack.get("namespace") != self.binding.namespace
                or ack.get("durable") is not True
                or not isinstance(ack.get("checkpoint"), str)
                or not 1 <= len(ack["checkpoint"]) <= 4096
            ):
                raise ValueError("Unproven acknowledgement")
            return DurableAck(
                evidence.id, self.binding.namespace, ack["checkpoint"], evidence.digest
            )
        except Exception:
            raise unavailable("recovery_protection_unavailable") from None

    def checkpoint(self, after=None):
        try:
            response = self.client.get(
                self.binding.checkpoint_path,
                params={"namespace": self.binding.namespace, **({"after": after} if after else {})},
            )
            response.raise_for_status()
            body = response.json()
            if (
                body["namespace"] != self.binding.namespace
                or body["complete"] is not True
                or not isinstance(body.get("records"), list)
                or len(body["records"]) > 1000
                or not isinstance(body.get("checkpoint"), str)
                or not 1 <= len(body["checkpoint"]) <= 4096
                or any(
                    not isinstance(row.get("revision"), str)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,18}", row["revision"])
                    for row in body["records"]
                )
            ):
                raise ValueError()
            records = [
                Evidence(**{**row, "revision": int(row["revision"])}) for row in body["records"]
            ]
            actual = hashlib.sha256(
                json.dumps(body["records"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if actual != body["page_digest"]:
                raise ValueError()
            return records, body["checkpoint"]
        except Exception:
            raise unavailable("recovery_checkpoint_unavailable") from None

    def _checkpoint_json(self, params, timeout_seconds):
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 5
        ):
            raise ValueError("Page deadline must be positive and at most five seconds")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._checkpoint_json_async(params, timeout_seconds))
        raise ValueError("Call the synchronous checkpoint adapter from a worker thread")

    async def _checkpoint_json_async(self, params, timeout_seconds):
        deadline = time.monotonic() + timeout_seconds
        # A total cancellation deadline includes response-header trickling, which
        # a sequence of individually successful socket reads would not bound.
        async with asyncio.timeout(timeout_seconds):
            async with httpx.AsyncClient(
                base_url=self.binding.origin,
                verify=self.binding.ca_file or True,
                follow_redirects=False,
                trust_env=False,
                headers={
                    "Authorization": self.client.headers["Authorization"],
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                transport=self.checkpoint_transport,
            ) as client:
                async with client.stream(
                    "GET",
                    self.binding.paged_checkpoint_path,
                    params=params,
                    timeout=timeout_seconds / 4,
                ) as response:
                    response.raise_for_status()
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise ValueError("Compressed checkpoint response unsupported")
                    raw = bytearray()
                    # Do not aggregate tiny transport chunks before deadline checks.
                    async for chunk in response.aiter_bytes():
                        if (
                            len(raw) + len(chunk) > CHECKPOINT_MAX_BYTES
                            or time.monotonic() >= deadline
                        ):
                            raise ValueError("Checkpoint page resource bound exceeded")
                        raw.extend(chunk)
                    result = json.loads(raw, object_pairs_hook=_unique_object)
                    if time.monotonic() >= deadline:
                        raise ValueError("Checkpoint page deadline exceeded")
                    return result

    def checkpoint_page(
        self,
        *,
        after=None,
        snapshot_checkpoint=None,
        cursor=None,
        page_size=1000,
        timeout_seconds=5,
    ):
        if (
            self.binding.paged_checkpoint_version != PAGED_CHECKPOINT_VERSION
            or not self.binding.paged_checkpoint_path
        ):
            raise unavailable("recovery_checkpoint_paging_unavailable")
        try:
            for value in (after, snapshot_checkpoint, cursor):
                _token(value, optional=True)
            if (
                (snapshot_checkpoint is None) != (cursor is None)
                or type(page_size) is not int
                or not 1 <= page_size <= 1000
            ):
                raise ValueError("Invalid checkpoint continuation")
            body = self._checkpoint_json(
                {
                    "version": PAGED_CHECKPOINT_VERSION,
                    "namespace": self.binding.namespace,
                    "limit": str(page_size),
                    **({"after": after} if after is not None else {}),
                    **(
                        {"checkpoint": snapshot_checkpoint, "cursor": cursor}
                        if cursor is not None
                        else {}
                    ),
                },
                timeout_seconds,
            )
            if not isinstance(body, dict) or set(body) != {
                "version",
                "namespace",
                "after",
                "checkpoint",
                "request_cursor",
                "total_records",
                "records",
                "next_cursor",
                "complete",
                "page_digest",
            }:
                raise ValueError("Unsupported checkpoint page schema")
            _token(body["checkpoint"])
            _token(body["next_cursor"], optional=True)
            total = _decimal(body["total_records"])
            if (
                body["version"] != PAGED_CHECKPOINT_VERSION
                or body["namespace"] != self.binding.namespace
                or body["after"] != after
                or body["request_cursor"] != cursor
                or (snapshot_checkpoint is not None and body["checkpoint"] != snapshot_checkpoint)
                or type(body["complete"]) is not bool
                or body["complete"] != (body["next_cursor"] is None)
                or not isinstance(body["records"], list)
                or len(body["records"]) > page_size
                or len(body["records"]) > total
                or (not body["complete"] and not body["records"])
                or not isinstance(body["page_digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", body["page_digest"])
                or checkpoint_page_digest(body) != body["page_digest"]
            ):
                raise ValueError("Unproven checkpoint page")
            records = tuple(
                Evidence(**{**row, "revision": _decimal(row["revision"])})
                for row in body["records"]
            )
            if len({record.id for record in records}) != len(records):
                raise ValueError("Duplicate evidence ID")
            return CheckpointPage(
                self.binding.namespace,
                after,
                body["checkpoint"],
                cursor,
                total,
                records,
                body["next_cursor"],
                body["complete"],
                body["page_digest"],
            )
        except Exception:
            raise unavailable("recovery_checkpoint_unavailable") from None

    def close(self):
        self.client.close()


def append_verified(store, evidence):
    """Require a matching durable acknowledgement even for non-HTTP adapters."""
    ack = store.append(evidence)
    namespace = getattr(getattr(store, "binding", None), "namespace", None)
    if (
        not isinstance(ack, DurableAck)
        or ack.evidence_id != evidence.id
        or ack.digest != evidence.digest
        or not isinstance(ack.namespace, str)
        or not ack.namespace
        or (namespace is not None and ack.namespace != namespace)
        or not isinstance(ack.checkpoint, str)
        or not 1 <= len(ack.checkpoint) <= 4096
    ):
        raise unavailable("recovery_protection_unproven")
    return ack


def collect_checkpoint(
    store: PagedEvidenceStore,
    consume_page: Callable[[CheckpointPage], None],
    *,
    after=None,
    page_size=1000,
    max_pages=10000,
    max_records=1000000,
    deadline_seconds=300,
) -> CheckpointCollection:
    """Stream pages to staging; only the returned summary proves complete enumeration.

    A sink must not publish readiness or authoritative state from partial pages.
    A failed scan is discarded or explicitly reconciled by the restore coordinator.
    """
    if (
        any(type(value) is not int or value < 1 for value in (max_pages, max_records, page_size))
        or page_size > 1000
        or type(deadline_seconds) not in (int, float)
        or not math.isfinite(deadline_seconds)
        or deadline_seconds <= 0
    ):
        raise ValueError("Positive bounded scan limits required")
    try:
        _token(after, optional=True)
        namespace = store.binding.namespace
        _token(namespace)
        binding_digest = checkpoint_binding_digest(store.binding)
        deadline = time.monotonic() + deadline_seconds
        checkpoint = cursor = total = None
        seen_ids, seen_cursors = set(), set()
        for number in range(1, max_pages + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or checkpoint_binding_digest(store.binding) != binding_digest:
                raise ValueError("Checkpoint collection deadline exceeded")
            page = store.checkpoint_page(
                after=after,
                snapshot_checkpoint=checkpoint,
                cursor=cursor,
                page_size=page_size,
                timeout_seconds=min(5, remaining),
            )
            # Validate even non-HTTP implementations at this collection boundary.
            if not isinstance(page, CheckpointPage):
                raise ValueError("Unsupported page object")
            _token(page.checkpoint)
            _token(page.next_cursor, optional=True)
            if (
                time.monotonic() >= deadline
                or checkpoint_binding_digest(store.binding) != binding_digest
                or page.namespace != namespace
                or page.after != after
                or page.request_cursor != cursor
                or (checkpoint is not None and page.checkpoint != checkpoint)
                or type(page.total_records) is not int
                or not 0 <= page.total_records <= max_records
                or (total is not None and page.total_records != total)
                or type(page.complete) is not bool
                or page.complete != (page.next_cursor is None)
                or not isinstance(page.records, tuple)
                or len(page.records) > page_size
                or any(not isinstance(record, Evidence) for record in page.records)
                or (not page.complete and not page.records)
                or (page.next_cursor is not None and page.next_cursor in seen_cursors)
            ):
                raise ValueError("Inconsistent checkpoint enumeration")
            checkpoint, total = page.checkpoint, page.total_records
            identifiers = {record.id for record in page.records}
            if len(identifiers) != len(page.records) or seen_ids.intersection(identifiers):
                raise ValueError("Duplicate evidence ID")
            seen_ids.update(identifiers)
            if (
                len(seen_ids) > total
                or (page.complete and len(seen_ids) != total)
                or (not page.complete and len(seen_ids) >= total)
            ):
                raise ValueError("Checkpoint count mismatch")
            digest_body = {
                "version": PAGED_CHECKPOINT_VERSION,
                "namespace": page.namespace,
                "after": page.after,
                "checkpoint": page.checkpoint,
                "request_cursor": page.request_cursor,
                "total_records": str(total),
                "records": [
                    {**asdict(record), "revision": str(record.revision)} for record in page.records
                ],
                "next_cursor": page.next_cursor,
                "complete": page.complete,
            }
            if checkpoint_page_digest(digest_body) != page.page_digest:
                raise ValueError("Page integrity mismatch")
            consume_page(page)
            if (
                time.monotonic() >= deadline
                or checkpoint_binding_digest(store.binding) != binding_digest
            ):
                raise ValueError("Checkpoint collection deadline exceeded")
            if page.complete:
                return CheckpointCollection(
                    namespace, after, checkpoint, number, len(seen_ids), binding_digest
                )
            cursor = page.next_cursor
            seen_cursors.add(cursor)
        raise ValueError("Checkpoint page limit exceeded")
    except Exception:
        raise unavailable("recovery_checkpoint_unavailable") from None
