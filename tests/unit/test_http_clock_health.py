import asyncio
from datetime import UTC, datetime, timedelta
import json
from threading import Event, get_ident
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Request

import appchi.http as protocol
from appchi.request_budget import deadline


def application(clock):
    app = protocol.create_http_app(None)
    app.state.settings = SimpleNamespace(
        environment="development",
        role="product-api",
        clock_health_file=clock,
        database_clock_health_file=clock,
    )
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "seconds", "code"),
    [
        ("/api/tenants/test/alerts/counts", 10, "request_timeout"),
        ("/api/ingest/v1/alerts", 5, "ingress_timeout"),
    ],
)
async def test_blocked_clock_read_keeps_loop_and_request_deadline_responsive(
    monkeypatch, path, seconds, code
):
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    finished = asyncio.Event()
    release = Event()
    timeouts = []
    calls = []

    class BlockedClock:
        def read_bytes(self):
            loop.call_soon_threadsafe(entered.set)
            try:
                # Backstop prevents a regressed inline read from hanging the suite.
                assert release.wait(5), "clock worker was not released"
                return b"{}"
            finally:
                loop.call_soon_threadsafe(finished.set)

    def controlled_timeout(value):
        scope = asyncio.timeout(None)
        timeouts.append((value, scope))
        return scope

    # Expire the real middleware cancellation scope on demand, without sleeps.
    monkeypatch.setattr(
        protocol,
        "asyncio",
        SimpleNamespace(timeout=controlled_timeout, to_thread=asyncio.to_thread),
    )
    app = application(BlockedClock())

    @app.post(path)
    async def mutation():
        calls.append("mutation")
        return {"ok": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://clock.test"
    ) as client:
        blocked = asyncio.create_task(client.post(path, json={}))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert not blocked.done()
            assert timeouts[0][0] == seconds
            healthy = await asyncio.wait_for(client.get("/livez"), 2)
            assert healthy.status_code == 200
            assert not finished.is_set()
            timeouts[0][1].reschedule(loop.time())
            response = await asyncio.wait_for(blocked, 2)
            assert response.status_code == 503
            assert response.json()["error"]["code"] == code
            assert response.headers["Retry-After"] == "5"
            assert not finished.is_set()
            assert not calls
        finally:
            release.set()
            await asyncio.wait_for(finished.wait(), 2)
            if not blocked.done():
                blocked.cancel()
            await asyncio.gather(blocked, return_exceptions=True)


@pytest.mark.asyncio
async def test_clock_offload_propagates_budget(monkeypatch):
    observed = []
    main_thread = get_ident()

    def clock_check(settings):
        observed.append((deadline.get(), get_ident()))

    monkeypatch.setattr("appchi.clock_health.require_clock_health", clock_check)
    app = application(None)

    @app.post("/api/tenants/test/probe")
    async def probe(request: Request):
        assert observed[0][0] == deadline.get()
        assert request.state.received_at.tzinfo is UTC
        return {"ok": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://clock.test"
    ) as client:
        response = await client.post("/api/tenants/test/probe", json={})
    assert response.status_code == 200
    assert observed[0][0] is not None
    assert observed[0][1] != main_thread


@pytest.mark.asyncio
@pytest.mark.parametrize("publication_ahead", [0, 2])
async def test_queued_check_uses_current_evidence_time_without_changing_received_at(
    monkeypatch, tmp_path, publication_ahead
):
    received_at = datetime(2026, 10, 7, tzinfo=UTC)
    check_at = received_at + timedelta(seconds=2)
    queued = asyncio.Event()
    release = asyncio.Event()

    class AdmissionClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return received_at

    class CheckClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return check_at

    async def queued_to_thread(function, *args, **kwargs):
        queued.set()
        await release.wait()
        return await asyncio.to_thread(function, *args, **kwargs)

    monkeypatch.setattr(protocol, "datetime", AdmissionClock)
    monkeypatch.setattr("appchi.clock_health.datetime", CheckClock)
    monkeypatch.setattr(
        protocol,
        "asyncio",
        SimpleNamespace(timeout=asyncio.timeout, to_thread=queued_to_thread),
    )
    clock = tmp_path / "clock.json"

    def publish(measured_at):
        clock.write_text(
            json.dumps(
                {
                    "measured_at": measured_at.isoformat(),
                    "synchronized": True,
                    "offset_seconds": 0,
                }
            )
        )

    publish(received_at)
    app = application(clock)
    called = []

    @app.post("/api/tenants/test/probe")
    async def probe(request: Request):
        called.append(request.state.received_at)
        return {"ok": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://clock.test"
    ) as client:
        request = asyncio.create_task(client.post("/api/tenants/test/probe", json={}))
        try:
            await asyncio.wait_for(queued.wait(), 2)
            # A new owner publication arrives while this request awaits a worker.
            publish(check_at + timedelta(seconds=publication_ahead))
            release.set()
            response = await asyncio.wait_for(request, 2)
            if publication_ahead:
                assert response.status_code == 503
                assert response.json()["error"]["code"] == "clock_untrusted"
                assert not called
            else:
                assert response.status_code == 200
                assert called == [received_at]
        finally:
            release.set()
            if not request.done():
                request.cancel()
            await asyncio.gather(request, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [False, True])
async def test_clock_evidence_still_fails_closed(tmp_path, valid):
    clock = tmp_path / "clock.json"
    clock.write_text(
        json.dumps(
            {
                "measured_at": datetime.now(UTC).isoformat(),
                "synchronized": valid,
                "offset_seconds": 0,
            }
        )
    )
    app = application(clock)
    called = []

    @app.post("/api/tenants/test/probe")
    async def probe():
        called.append(True)
        return {"ok": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://clock.test"
    ) as client:
        response = await client.post("/api/tenants/test/probe", json={})
    assert response.status_code == (200 if valid else 503)
    assert bool(called) is valid
    if not valid:
        assert response.json()["error"]["code"] == "clock_untrusted"
