"""What the shared HTTP layer records for each request."""

import logging
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

import keep.http as protocol
from keep.observability.metrics import REGISTRY
from keep.shared.errors import AppError

TENANT, ALERT = str(uuid4()), str(uuid4())
DETAIL = "/api/tenants/{tenant_id}/alerts/{alert_id}"


def application():
    app = protocol.create_http_app(None)
    app.state.settings = SimpleNamespace(
        environment="development",
        role="product-api",
        clock_health_file=None,
        database_clock_health_file=None,
    )

    @app.get(DETAIL)
    async def detail(tenant_id: str, alert_id: str):
        return {"data": {"id": alert_id}}

    @app.post("/api/tenants/{tenant_id}/alerts/{alert_id}/commands")
    async def command(tenant_id: str, alert_id: str):
        raise AppError("revision_conflict", "The alert changed.", 409)

    @app.get("/api/tenants/{tenant_id}/broken")
    async def broken(tenant_id: str):
        raise RuntimeError("canary-password=hunter2")

    return app


def sample(name, **labels):
    return REGISTRY.get_sample_value(name, labels) or 0.0


async def call(app, method, path, **options):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="https://keep.test") as client:
        return await client.request(method, path, **options)


def events(caplog, name):
    return [r for r in caplog.records if getattr(r, "keep_event", None) == name]


@pytest.mark.asyncio
async def test_each_request_leaves_one_record_carrying_its_request_id(caplog):
    """Requirements: REV-74; observability 2 and 7."""
    labels = dict(service="api", route=DETAIL, method="GET", status="200")
    before = sample("keep_http_requests_total", **labels)
    good = sample("keep_sli_requests_total", sli="read", outcome="good", reason="ok")
    with caplog.at_level(logging.INFO, logger="keep.http"):
        response = await call(application(), "GET", f"/api/tenants/{TENANT}/alerts/{ALERT}")
    assert response.status_code == 200
    (record,) = events(caplog, "http_request")
    fields = record.keep_fields
    assert fields["request_id"] == response.headers["X-Request-ID"]
    assert fields["route"] == DETAIL and fields["method"] == "GET" and fields["status"] == 200
    assert fields["tenant_id"] == TENANT and fields["alert_id"] == ALERT
    assert fields["sli"] == "read" and record.keep_outcome == "success"
    assert record.levelno == logging.INFO
    assert sample("keep_http_requests_total", **labels) == before + 1
    assert sample("keep_sli_requests_total", sli="read", outcome="good", reason="ok") == good + 1


@pytest.mark.asyncio
async def test_every_error_code_is_recorded_where_the_envelope_is_built(caplog, monkeypatch):
    """Requirements: REV-74; observability 2 and 8; reliability 3."""
    monkeypatch.setattr("keep.clock_health.require_clock_health", lambda *a, **k: None)
    route = "/api/tenants/{tenant_id}/alerts/{alert_id}/commands"
    errors = dict(service="api", route=route, code="revision_conflict")
    before = sample("keep_http_errors_total", **errors)
    excluded = dict(sli="command", outcome="excluded", reason="conflict")
    counted = sample("keep_sli_requests_total", **excluded)
    with caplog.at_level(logging.INFO, logger="keep.http"):
        response = await call(
            application(), "POST", f"/api/tenants/{TENANT}/alerts/{ALERT}/commands", json={"a": 1}
        )
    assert response.status_code == 409
    (record,) = events(caplog, "http_request")
    assert record.keep_fields["error_code"] == "revision_conflict"
    assert record.keep_fields["status"] == 409 and record.keep_fields["body_bytes"] == 7
    assert record.keep_outcome == "failure"
    assert sample("keep_http_errors_total", **errors) == before + 1
    assert sample("keep_sli_requests_total", **excluded) == counted + 1


@pytest.mark.asyncio
async def test_an_unhandled_error_is_recorded_without_its_text(caplog):
    """Requirements: REV-74; observability 4. A 500 is no longer silent."""
    route = "/api/tenants/{tenant_id}/broken"
    before = sample("keep_http_unhandled_errors_total", service="api", route=route)
    bad = dict(sli="read", outcome="bad", reason="server_error")
    counted = sample("keep_sli_requests_total", **bad)
    with caplog.at_level(logging.INFO, logger="keep.http"):
        response = await call(application(), "GET", f"/api/tenants/{TENANT}/broken")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    (failure,) = events(caplog, "http_unhandled_error")
    assert failure.levelno == logging.ERROR
    assert failure.keep_fields["error_class"] == "builtins.RuntimeError"
    # The 500 is built outside the protocol middleware, so the ID is in its body.
    assert failure.keep_fields["request_id"] == response.json()["error"]["request_id"]
    assert "test_observability_http.py" in failure.keep_fields["stack"]
    (request,) = events(caplog, "http_request")
    assert request.levelno == logging.WARNING
    assert request.keep_fields["status"] == 500
    assert request.keep_fields["error_code"] == "internal_error"
    assert "hunter2" not in caplog.text
    assert "hunter2" not in str([r.__dict__ for r in caplog.records if r.name == "keep.http"])
    assert sample("keep_http_unhandled_errors_total", service="api", route=route) == before + 1
    assert sample("keep_sli_requests_total", **bad) == counted + 1


@pytest.mark.asyncio
async def test_a_passing_probe_is_counted_but_not_logged(caplog):
    """Requirements: REV-74; observability 5."""
    labels = dict(service="api", route="/livez", method="GET", status="200")
    before = sample("keep_http_requests_total", **labels)
    with caplog.at_level(logging.INFO, logger="keep.http"):
        response = await call(application(), "GET", "/livez")
    assert response.status_code == 200
    assert not events(caplog, "http_request")
    assert sample("keep_http_requests_total", **labels) == before + 1


@pytest.mark.asyncio
async def test_metrics_are_not_served_on_the_application_port(caplog):
    """Requirements: REV-74; observability 7."""
    with caplog.at_level(logging.INFO, logger="keep.http"):
        response = await call(application(), "GET", "/metrics")
    assert response.status_code == 404
    (record,) = events(caplog, "http_request")
    assert record.keep_fields["route"] == "unmatched" and record.keep_fields["sli"] == "unmatched"
