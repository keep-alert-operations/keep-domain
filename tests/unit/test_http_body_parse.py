"""The protocol middleware parses a JSON body once and leaves the value for the handler."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import Request

import appchi.http as protocol
from appchi.ingestion.native import parse_json


@pytest.fixture
def parses(monkeypatch):
    calls = []

    def counted(raw):
        calls.append(raw)
        return parse_json(raw)

    monkeypatch.setattr(protocol, "parse_json", counted)
    return calls


def application():
    app = protocol.create_http_app(None)
    app.state.settings = SimpleNamespace(
        environment="development", role="product-api", clock_health_file=None
    )
    seen = []

    @app.post("/api/ingest/v1/alerts")
    @app.post("/auth/login")
    @app.get("/api/tenants/test/items")
    async def handler(request: Request):
        seen.append(getattr(request.state, "json_body", "absent"))
        return {"ok": True}

    return app, seen


async def send(app, method, path, content=None, headers=None):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://parse.test"
    ) as client:
        return await client.request(
            method,
            path,
            content=content,
            headers={"content-type": "application/json", **(headers or {})},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "value"),
    [
        (b'{"alerts": [{"payload": {"a": 1}}]}', {"alerts": [{"payload": {"a": 1}}]}),
        (b" null ", None),
        (b"[1, 2]", [1, 2]),
    ],
)
async def test_post_body_is_parsed_once_and_kept_on_request_state(parses, body, value):
    app, seen = application()
    response = await send(app, "POST", "/api/ingest/v1/alerts", body)
    assert response.status_code == 200
    assert seen == [value]
    assert parses == [body]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"", "invalid_json"),
        (b"{", "invalid_json"),
        (b'{"a":1,"a":2}', "duplicate_key"),
        (b'{"a":NaN}', "invalid_json"),
        (b'"\\ud800"', "invalid_json"),
        (b"\xff", "invalid_json"),
        (b"[" * 5000, "invalid_json"),
    ],
)
async def test_invalid_json_is_rejected_before_the_handler(parses, body, code):
    app, seen = application()
    response = await send(app, "POST", "/api/ingest/v1/alerts", body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == code
    assert response.headers["Cache-Control"] == "private, no-store"
    assert not seen
    assert parses == [body]


@pytest.mark.asyncio
async def test_unparsed_requests_leave_no_body_value(parses):
    app, seen = application()
    assert (await send(app, "GET", "/api/tenants/test/items")).status_code == 200
    assert (await send(app, "POST", "/auth/login", b"not json")).status_code == 200
    too_large = await send(app, "POST", "/api/ingest/v1/alerts", b" " * (4 * 1024 * 1024 + 1))
    assert too_large.status_code == 413
    assert too_large.json()["error"]["code"] == "body_too_large"
    media = await send(app, "POST", "/api/ingest/v1/alerts", b"{}", {"content-type": "text/plain"})
    assert media.status_code == 415
    assert seen == ["absent", "absent"]
    assert not parses
