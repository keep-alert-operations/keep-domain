"""A request is one flow: its steps wait for the commit, name the user, and reads do not flood."""

from contextlib import contextmanager
import logging
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

import keep.http as protocol
from keep import alert_notifications, db
from keep.observability import Flow, flow as alert_flow, http as observe
from keep.observability.metrics import REGISTRY
from keep.observability.testing import capture_records

TENANT, ALERT, USER = str(uuid4()), str(uuid4()), str(uuid4())
DETAIL = "/api/tenants/{tenant_id}/alerts/{alert_id}"
LOG = logging.getLogger("keep.test.requests")


def change(alert=ALERT, **fields):
    alert_flow.note(
        "alert_changed",
        alert={"id": alert, "application": "billing"},
        cause="set_status",
        status_before="firing",
        status_after="resolved",
        revision=2,
        **fields,
    )


def application():
    app = protocol.create_http_app(None)
    app.state.settings = SimpleNamespace(
        environment="development",
        role="product-api",
        clock_health_file=None,
        database_clock_health_file=None,
    )

    @app.get(DETAIL)
    def detail(tenant_id: str, alert_id: str, request: protocol.Request):
        observe.actor(request, USER, tenant_id)
        return {"data": {"id": alert_id}}

    @app.post("/api/tenants/{tenant_id}/alerts/counts")
    def counts(tenant_id: str, request: protocol.Request):
        observe.actor(request, USER, tenant_id)
        return {"data": []}

    @app.post(DETAIL + "/commands")
    def command(tenant_id: str, alert_id: str, request: protocol.Request):
        observe.actor(request, USER, tenant_id)
        change(principal_id=USER)
        alert_flow.active().settle()  # as the database does at commit
        return {"data": {"id": alert_id}}

    return app


async def call(app, method, path, **options):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="https://keep.test") as client:
        return await client.request(method, path, **options)


@pytest.fixture
def records():
    return capture_records("api", "product-api")


def database(monkeypatch):
    """A Database whose unit of work needs no server: only commit and rollback matter."""

    @contextmanager
    def unit(self, conn, tenant_id, guard, *, read_committed=False):
        yield

    @contextmanager
    def connection(timeout=None):
        yield SimpleNamespace()

    monkeypatch.setattr(db.Database, "_transaction", unit)
    store = db.Database.__new__(db.Database)
    store.pool = SimpleNamespace(connection=connection)
    store.deployment_epoch = None
    return store


def test_steps_noted_in_a_transaction_are_written_when_it_commits(records, monkeypatch):
    """Requirements: REV-74; observability 3. Nothing is said before the commit."""
    store = database(monkeypatch)
    with Flow(LOG) as flow:
        with store.transaction():
            change()
            assert records() == []
        (record,) = records()
        assert record["event"]["action"] == "alert_changed"
        assert flow.mark() == 0


def test_a_rolled_back_transaction_leaves_no_step(records, monkeypatch):
    """Requirements: REV-74; observability 3."""
    store = database(monkeypatch)
    with Flow(LOG):
        with pytest.raises(RuntimeError):
            with store.transaction():
                change()
                raise RuntimeError("rolled back")
        with store.transaction():
            pass
    assert records() == []


def test_an_inner_transaction_settles_only_its_own_steps(records, monkeypatch):
    """Requirements: REV-74; observability 3. The outer effect is not yet committed."""
    store = database(monkeypatch)
    other = str(uuid4())
    with Flow(LOG):
        with store.transaction():
            change()
            with store.transaction():
                change(other)
            assert [r["keep"]["alert"]["id"] for r in records()] == [other]
            with pytest.raises(RuntimeError):
                with store.transaction():
                    change(str(uuid4()))
                    raise RuntimeError("inner rolled back")
        assert [r["keep"]["alert"]["id"] for r in records()] == [other, ALERT]


@pytest.mark.asyncio
async def test_a_command_step_carries_the_request_and_the_user(records):
    """Requirements: REV-74; observability 2 and 3."""
    path = f"/api/tenants/{TENANT}/alerts/{ALERT}/commands"
    response = await call(application(), "POST", path, json={"kind": "set_status"})
    assert response.status_code == 200
    step, request = records()
    assert step["event"]["action"] == "alert_changed" and step["event"]["sequence"] == 1
    assert request["event"]["action"] == "http_request"
    for record in (step, request):
        assert record["http"]["request"]["id"] == response.headers["X-Request-ID"]
        assert record["user"]["id"] == USER
        assert record["keep"]["tenant_id"] == TENANT
        assert record["keep"]["alert"]["id"] == ALERT
    assert step["message"] == "Alert changed by set_status: status firing to resolved, revision 2"


@pytest.mark.asyncio
async def test_a_repeated_read_is_written_once_and_counted(records, monkeypatch):
    """Requirements: REV-74; observability 5. The UI refreshes; the log does not flood."""
    app = application()
    labels = dict(service="api", route=DETAIL, method="GET", status="200")
    before = REGISTRY.get_sample_value("keep_http_requests_total", labels) or 0.0
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr("keep.observability.logs.monotonic", lambda: clock.now)
    for _ in range(5):
        await call(app, "GET", f"/api/tenants/{TENANT}/alerts/{ALERT}")
    await call(app, "GET", f"/api/tenants/{TENANT}/alerts/{uuid4()}")
    clock.now += 61
    await call(app, "GET", f"/api/tenants/{TENANT}/alerts/{ALERT}")
    for _ in range(3):  # the feed's count refresh is a POST, and repeats the same way
        await call(app, "POST", f"/api/tenants/{TENANT}/alerts/counts", json={"items": []})
    written = [r for r in records() if r["event"]["action"] == "http_request"]
    assert [r["http"]["request"]["method"] for r in written].count("POST") == 1
    written = [r for r in written if r["http"]["request"]["method"] == "GET"]
    # The first read, the read of another alert, and the first after a minute.
    assert [r["keep"]["alert"]["id"] == ALERT for r in written] == [True, False, True]
    assert "repeats" not in written[0]["keep"] and written[2]["keep"]["repeats"] == 4
    assert REGISTRY.get_sample_value("keep_http_requests_total", labels) == before + 7


def test_authorization_outside_a_request_adds_nothing_and_does_not_fail(records):
    """Requirements: REV-74; observability 2. A live stream re-checks its grant this way."""
    observe.actor(SimpleNamespace(app=None), USER, TENANT)
    with Flow(LOG) as flow:
        observe.actor(SimpleNamespace(app=None), USER, TENANT)
        assert flow.fields == {"principal_id": USER, "tenant_id": TENANT}
    assert records() == []


def test_the_change_sent_to_kafka_is_a_step_and_a_failure_is_recorded_once(records, monkeypatch):
    """Requirements: REV-74; observability 3 and 5."""
    envelope = (
        '{"tenant_id":"%s","alert_id":"%s","event_id":"change-1","cause":"set_status"}'
        % (TENANT, ALERT)
    ).encode()
    produced = []
    publisher = SimpleNamespace(
        produce=lambda topic, key, value: produced.append(topic), flush=lambda timeout: 0
    )
    monkeypatch.setattr(alert_notifications, "_publisher", publisher)
    monkeypatch.setattr(alert_notifications, "_topic", "keep.test.alerts.changed")
    with Flow(LOG, principal_id=USER):
        alert_notifications.publish_best_effort([envelope])
        publisher.flush = lambda timeout: 1
        alert_notifications.publish_best_effort([envelope])
    sent, unconfirmed = records()
    assert sent["event"]["action"] == "alert_notification_published"
    assert sent["keep"]["changed_event_id"] == "change-1" and sent["keep"]["alert"]["id"] == ALERT
    assert sent["user"]["id"] == USER
    assert unconfirmed["event"]["action"] == "alert_notification_unconfirmed"
    assert unconfirmed["log"]["level"] == "warning" and unconfirmed["keep"]["count"] == 1
    assert produced == ["keep.test.alerts.changed"] * 2
