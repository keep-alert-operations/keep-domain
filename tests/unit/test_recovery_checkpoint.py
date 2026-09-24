"""Controlled HTTP contract tests; no supplied evidence-service guarantees assumed."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import asyncio
import json
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest

from appchi.recovery import evidence as module
from appchi.recovery.evidence import (
    Evidence,
    EvidenceBinding,
    HttpEvidenceStore,
    PAGED_CHECKPOINT_VERSION,
    collect_checkpoint,
)
from appchi.shared.errors import AppError


def record(index):
    return {
        "id": str(UUID(int=index + 1)),
        "tenant_id": str(UUID(int=10000)),
        "resource_kind": "alert",
        "resource_id": str(UUID(int=index + 20000)),
        "revision": str(index),
        "state": "final",
        "digest": "a" * 64,
    }


def signed(body):
    result = deepcopy(body)
    result.pop("page_digest", None)
    digest = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return {**result, "page_digest": digest}


def page(records, *, total=None, cursor=None, next_cursor=None, **changes):
    return signed(
        {
            "version": PAGED_CHECKPOINT_VERSION,
            "namespace": "fixture-independent",
            "after": None,
            "checkpoint": "opaque-snapshot",
            "request_cursor": cursor,
            "total_records": str(len(records) if total is None else total),
            "records": records,
            "next_cursor": next_cursor,
            "complete": next_cursor is None,
            **changes,
        }
    )


class Service:
    def __init__(self, pages):
        self.pages, self.requests = pages, []

    def __call__(self, request):
        self.requests.append(request)
        value = self.pages[len(self.requests) - 1]
        return value if isinstance(value, httpx.Response) else httpx.Response(200, json=value)


@pytest.fixture
def store():
    binding = EvidenceBinding(
        "https://evidence.test",
        "/append",
        "/legacy-checkpoint",
        "fixture-independent",
        "fixture-independence",
        "fixture-durability",
        paged_checkpoint_path="/snapshot-pages",
        paged_checkpoint_version=PAGED_CHECKPOINT_VERSION,
    )
    result = HttpEvidenceStore(binding, "fixture-secret")
    result.client.close()
    yield result
    result.close()


def serve(store, pages):
    service = Service(pages)
    store.checkpoint_transport = httpx.MockTransport(service)
    store.client = httpx.Client(
        base_url=store.binding.origin,
        transport=httpx.MockTransport(service),
        headers={"Authorization": "Bearer fixture-secret"},
    )
    return service


def test_more_than_one_thousand_records_use_one_fixed_snapshot(store):
    cursor = "opaque/cursor?plus=+&unicode=Ω"
    service = serve(
        store,
        [
            page(
                [record(i) for i in range(1000)],
                total=1001,
                next_cursor=cursor,
                after="lower-checkpoint",
            ),
            page([record(1000)], total=1001, cursor=cursor, after="lower-checkpoint"),
        ],
    )
    consumed = []
    result = collect_checkpoint(
        store, lambda value: consumed.append(len(value.records)), after="lower-checkpoint"
    )
    assert result.records == 1001 and result.pages == 2 and result.checkpoint == "opaque-snapshot"
    assert result.binding_digest == module.checkpoint_binding_digest(store.binding)
    assert consumed == [1000, 1]
    first, second = service.requests
    assert first.url.path == "/snapshot-pages" and "checkpoint" not in first.url.params
    assert (
        second.url.params["cursor"] == cursor
        and second.url.params["checkpoint"] == result.checkpoint
    )
    assert (
        second.url.params["namespace"] == "fixture-independent"
        and second.url.params["after"] == "lower-checkpoint"
    )
    assert first.headers["accept-encoding"] == "identity"
    assert all(value <= 1.25 for value in first.extensions["timeout"].values())


def test_empty_complete_snapshot_is_supported(store):
    serve(store, [page([])])
    consumed = []
    result = collect_checkpoint(store, consumed.append)
    assert result.records == 0 and result.pages == 1 and consumed[0].complete


@pytest.mark.parametrize(
    "change",
    [
        {"namespace": "wrong"},
        {"after": "wrong"},
        {"checkpoint": "changed-snapshot"},
        {"request_cursor": "wrong"},
        {"version": "unknown"},
        {"total_records": "3"},
        {"total_records": "02"},
        {"total_records": 2},
        {"total_records": "9223372036854775808"},
        {"complete": 1},
        {"complete": False},
        {"next_cursor": "cursor1", "complete": False},
        {"records": [record(0)]},
        {"records": []},
    ],
)
def test_cross_page_changes_truncation_and_loops_never_complete(store, change):
    serve(
        store,
        [
            page([record(0)], total=2, next_cursor="cursor1"),
            signed({**page([record(1)], total=2, cursor="cursor1"), **change}),
        ],
    )
    consumed = []
    with pytest.raises(AppError, match="recovery_checkpoint_unavailable"):
        collect_checkpoint(store, consumed.append, page_size=1)
    assert len(consumed) == 1  # staging must be discarded; no complete summary returned


def test_digest_binds_metadata_and_record_content(store):
    body = page([record(0)])
    body["checkpoint"] = "tampered-after-signing"
    serve(store, [body])
    with pytest.raises(AppError):
        collect_checkpoint(store, lambda page: pytest.fail("Corrupt page must not reach staging"))


def test_duplicate_ids_inside_page_rejected(store):
    serve(store, [page([record(0), record(0)])])
    with pytest.raises(AppError):
        collect_checkpoint(store, lambda page: pytest.fail("Duplicate page must not reach staging"))


@pytest.mark.parametrize("limits,staged", [({"max_records": 1}, 0), ({"max_pages": 1}, 1)])
def test_explicit_collection_limits_leave_no_complete_summary(store, limits, staged):
    serve(
        store,
        [
            page([record(0)], total=2, next_cursor="cursor1"),
            page([record(1)], total=2, cursor="cursor1"),
        ],
    )
    consumed = []
    with pytest.raises(AppError):
        collect_checkpoint(store, consumed.append, **limits)
    assert len(consumed) == staged


def test_collector_revalidates_non_http_page_objects(store):
    serve(store, [page([record(0)])])
    good = store.checkpoint_page()
    fake = SimpleNamespace(
        binding=store.binding, checkpoint_page=lambda **kwargs: replace(good, page_digest="0" * 64)
    )
    with pytest.raises(AppError):
        collect_checkpoint(fake, lambda page: pytest.fail("Unverified adapter page"))


def test_binding_change_during_scan_cannot_complete(store):
    service = serve(
        store,
        [
            page([record(0)], total=2, next_cursor="cursor1"),
            page([record(1)], total=2, cursor="cursor1"),
        ],
    )

    def replace_binding(page):
        store.binding = replace(store.binding, durability_evidence="different-qualification")

    with pytest.raises(AppError):
        collect_checkpoint(store, replace_binding)
    assert len(service.requests) == 1


class Chunks(httpx.SyncByteStream, httpx.AsyncByteStream):
    def __init__(self, values, tick=None):
        self.values, self.tick, self.closed = values, tick, False

    def __iter__(self):
        for value in self.values:
            if self.tick:
                self.tick()
            yield value

    def close(self):
        self.closed = True

    async def __aiter__(self):
        for chunk in self:
            yield chunk

    async def aclose(self):
        self.close()


def test_response_byte_limit_closes_stream(store):
    stream = Chunks([b"x" * 1024 * 1024] * 5)
    serve(store, [httpx.Response(200, stream=stream)])
    with pytest.raises(AppError):
        store.checkpoint_page()
    assert stream.closed


def test_trickled_chunks_cannot_extend_page_deadline(store, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    stream = Chunks([b" "] * 10, lambda: clock.__setitem__(0, clock[0] + 2))
    serve(store, [httpx.Response(200, stream=stream)])
    with pytest.raises(AppError):
        store.checkpoint_page()
    assert stream.closed and clock[0] == 6


def test_staging_time_counts_towards_collection_deadline(store, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    serve(store, [page([record(0)])])
    with pytest.raises(AppError):
        collect_checkpoint(store, lambda page: clock.__setitem__(0, 6), deadline_seconds=5)


def test_total_network_deadline_cancels_slow_response_headers(store):
    cancelled = []

    async def slow_headers(request):
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    store.checkpoint_transport = httpx.MockTransport(slow_headers)
    with pytest.raises(AppError):
        store.checkpoint_page(timeout_seconds=0.02)
    assert cancelled == [True]


def test_redirects_duplicate_json_keys_and_compression_are_rejected(store):
    responses = [
        httpx.Response(302, headers={"Location": "https://other.test/secret"}),
        httpx.Response(200, content=b'{"namespace":"one","namespace":"two"}'),
        httpx.Response(200, content=b"compressed", headers={"Content-Encoding": "br"}),
    ]
    for response in responses:
        store.client.close()
        service = serve(store, [response])
        with pytest.raises(AppError):
            store.checkpoint_page()
        assert len(service.requests) == 1


def test_legacy_checkpoint_and_append_remain_supported(store):
    wire_record = record(0)
    evidence = Evidence(**{**wire_record, "revision": 0})
    digest = hashlib.sha256(
        json.dumps([wire_record], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    service = serve(
        store,
        [
            {
                "namespace": store.binding.namespace,
                "complete": True,
                "records": [wire_record],
                "checkpoint": "legacy",
                "page_digest": digest,
            },
            {
                "evidence_id": evidence.id,
                "namespace": store.binding.namespace,
                "checkpoint": "append",
                "digest": evidence.digest,
                "durable": True,
            },
        ],
    )
    assert store.checkpoint() == ([evidence], "legacy")
    assert store.append(evidence).evidence_id == evidence.id
    assert service.requests[0].url.path == "/legacy-checkpoint"


def test_paging_requires_explicit_service_binding(store):
    store.binding = replace(
        store.binding, paged_checkpoint_path=None, paged_checkpoint_version=None
    )
    service = serve(store, [])
    with pytest.raises(AppError, match="recovery_checkpoint_paging_unavailable"):
        store.checkpoint_page()
    assert service.requests == []
    with pytest.raises(ValueError):
        replace(store.binding, paged_checkpoint_path="/pages")
    with pytest.raises(ValueError):
        replace(
            store.binding, paged_checkpoint_path="/pages", paged_checkpoint_version="unsupported"
        )
