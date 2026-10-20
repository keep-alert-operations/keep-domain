"""Tenant coordinator critical section: fewer statements, unchanged results.

These fakes model only the statements under test. PostgreSQL semantics of the
folded statements are covered by the processor's real-database test.
"""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import json
from uuid import UUID, uuid4

import pytest

from appchi import db as database_module
from appchi.alerts import processor, repository
from appchi.alerts.lifecycle import apply_source
from appchi.events import changed
from appchi.incidents.state import lock_linked_incidents
from appchi.request_budget import request_budget
from appchi.shared.errors import AppError
from appchi.shared.transactions import advance_clock, coordinator

BASE = datetime(2026, 10, 18, tzinfo=UTC)


def normalized(query):
    if hasattr(query, "as_string"):
        query = query.as_string(None)
    return " ".join(str(query).split())


class Result:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.position = 0

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def __iter__(self):
        return self

    def __next__(self):
        if self.position >= len(self.rows):
            raise StopIteration
        self.position += 1
        return self.rows[self.position - 1]


class FakeConn:
    """Records statements, pipeline depth and answers configured patterns."""

    def __init__(self, answers=(), *, work=None, clock=BASE):
        self.answers = list(answers)
        self.work = work
        self.clock = clock
        self.statements = []
        self.depth = 0
        self.events = []

    @contextmanager
    def pipeline(self):
        self.depth += 1
        self.events.append("pipeline-enter")
        try:
            yield
        finally:
            self.depth -= 1
            self.events.append("pipeline-exit")

    def execute(self, query, params=()):
        text = normalized(query)
        self.statements.append((text, params, self.depth))
        self.events.append(text)
        if self.work is not None and text.startswith("SELECT * FROM tenant_work_state"):
            return Result([dict(self.work)] if self.work.get("tenant_id") else [])
        if self.work is not None and "UPDATE tenant_work_state t SET last_clock=c.now" in text:
            last = self.work["last_clock"]
            if last is not None and self.clock < last:
                return Result()
            self.work["last_clock"] = self.clock
            self.work["admission_order"] += params[0]
            return Result([{"now": self.clock, "admission_order": self.work["admission_order"]}])
        for pattern, rows in self.answers:
            if pattern in text:
                return Result(rows(params) if callable(rows) else rows)
        return Result()

    def texts(self):
        return [text for text, _, _ in self.statements]

    def matching(self, fragment):
        return [entry for entry in self.statements if fragment in entry[0]]


def work_row(tenant, last_clock=None):
    return {
        "tenant_id": tenant,
        "admission_order": 4,
        "change_order": 10,
        "projection_seq": 20,
        "last_clock": last_clock,
        "blocked": False,
        "next_attempt_at": BASE - timedelta(days=1),
    }


# Coordinator and clock check


def test_coordinator_returns_locked_row_and_clock_in_two_statements():
    tenant = uuid4()
    conn = FakeConn(work=work_row(tenant, BASE - timedelta(seconds=1)))
    state, now = coordinator(conn, tenant)
    assert now == BASE
    assert state["last_clock"] == BASE - timedelta(seconds=1)  # the row as locked
    assert conn.work["last_clock"] == BASE
    assert conn.work["admission_order"] == 4  # plain coordinator allocates nothing
    lock, clock = conn.texts()
    # Row-lock strength is unchanged: FOR UPDATE, not an UPDATE's NO KEY lock.
    assert lock == "SELECT * FROM tenant_work_state WHERE tenant_id=%s FOR UPDATE"
    assert "MATERIALIZED (SELECT clock_timestamp() AS now)" in clock
    assert "c.now>=t.last_clock" in clock


@pytest.mark.parametrize("last_clock", [None, BASE])
def test_unset_or_equal_clock_is_accepted(last_clock):
    tenant = uuid4()
    conn = FakeConn(work=work_row(tenant, last_clock))
    assert coordinator(conn, tenant)[1] == BASE


def test_clock_regression_raises_and_leaves_the_row_unchanged():
    tenant = uuid4()
    conn = FakeConn(work=work_row(tenant, BASE + timedelta(microseconds=1)))
    with pytest.raises(AppError) as raised:
        coordinator(conn, tenant)
    assert raised.value.code == "clock_untrusted"
    assert conn.work["last_clock"] == BASE + timedelta(microseconds=1)


def test_missing_coordinator_row_is_not_found():
    conn = FakeConn(work={"tenant_id": None})
    with pytest.raises(AppError) as raised:
        coordinator(conn, uuid4())
    assert raised.value.code == "not_found"


def test_admission_is_allocated_with_the_clock():
    tenant = uuid4()
    conn = FakeConn(work=work_row(tenant))
    assert advance_clock(conn, tenant, admission=True) == (BASE, 5)
    assert conn.statements[0][1] == (1, tenant)


# Source application body


def v1_item(tenant, **extra):
    payload = {
        "application": "app",
        "object": "cpu",
        "node_name": "n1",
        "message": "firing",
        "operator": "legacy",
        "time_created": "01-01-2026 00:00:00",
        "severity": "error",
    }
    return {
        "id": uuid4(),
        "tenant_id": tenant,
        "operator_id": None,
        "version": "v1",
        "key_field": "app|cpu|n1",
        "key_digest": b"digest",
        "identity_material": b"material",
        "received_at": BASE - timedelta(seconds=1),
        "admission_order": 5,
        "payload": payload,
        "raw_json": b"{}",
        "time_defaulted": False,
        "adapter_version": None,
        **extra,
    }


@pytest.fixture
def body(monkeypatch):
    """Run _apply_one with maintenance/publication collaborators stubbed."""
    from appchi.maintenance import runtime

    calls = {"lock_catalog": [], "publish": []}

    def lock_catalog(conn, catalog, *, targets=(), incidents=()):
        calls["lock_catalog"].append(list(targets))
        # The real lock_catalog always locks this alert's linked contexts.
        conn.execute("LOCK CONTEXTS FOR TARGETS", (list(targets),))

    def apply_transition(conn, before, after, when, order, cause, now, catalog):
        conn.execute("APPLY TRANSITION", ())
        adjusted = dict(after, revision=1, projection_version=1)
        if before is not None:
            adjusted["revision"] = before["revision"]
            adjusted["projection_version"] = before["projection_version"] + 1
        return adjusted, before is None, None

    def publish(conn, before, after, when, cause, **kwargs):
        calls["publish"].append(kwargs)
        return {"change_order": 11, "projection_seq": 21, "envelope": b"{}", "event_id": "evt"}

    monkeypatch.setattr(runtime, "lock_catalog", lock_catalog)
    monkeypatch.setattr(runtime, "apply_transition", apply_transition)
    monkeypatch.setattr(processor, "publish", publish)
    return calls


def test_new_alert_is_inserted_once_after_transition_without_second_coordinator(body):
    tenant = uuid4()
    item = v1_item(tenant)
    conn = FakeConn([("FROM alert_key_claims", [])])
    result = processor._apply_one(
        conn, tenant, None, None, supplied_item=item, coordinated=(work_row(tenant), BASE)
    )
    assert result["error_code"] is None
    assert result["event_id"] == "evt"
    texts = conn.texts()
    assert not [text for text in texts if "tenant_work_state" in text]
    identity = texts.index("INSERT INTO alert_identities(id,tenant_id) VALUES(%s,%s)")
    transition = texts.index("APPLY TRANSITION")
    inserts = [index for index, text in enumerate(texts) if text.startswith("INSERT INTO alerts")]
    assert identity < transition < inserts[0] and len(inserts) == 1
    assert not [text for text in texts if text.startswith("UPDATE alerts")]
    # The single INSERT carries the final transition state.
    (_, params, _) = conn.statements[inserts[0]]
    columns = list(apply_source(None, item)[0])
    stored = dict(zip(columns, params))
    assert stored["revision"] == 1 and stored["projection_version"] == 1
    (_, event, _) = conn.matching("INSERT INTO alert_source_events")[0]
    assert event[-1] is None
    assert not conn.matching("UPDATE alert_source_events")


def test_grafana_adapter_version_is_part_of_the_source_event_insert(body):
    tenant = uuid4()
    item = v1_item(tenant, adapter_version="appchi-grafana-v1")
    conn = FakeConn([("FROM alert_key_claims", [])])
    processor._apply_one(
        conn, tenant, None, None, supplied_item=item, coordinated=(work_row(tenant), BASE)
    )
    ((text, params, _),) = conn.matching("INSERT INTO alert_source_events")
    assert "occurrence_id,adapter_version)" in text
    assert params[-1] == "appchi-grafana-v1"
    assert not conn.matching("UPDATE alert_source_events")


def test_existing_alert_locks_linked_contexts_once(body):
    tenant = uuid4()
    item = v1_item(tenant)
    previous, _ = apply_source(None, item)
    previous = dict(previous, revision=3, projection_version=3)
    claim = {
        "alert_id": previous["id"],
        "key_field": item["key_field"],
        "identity_material": item["identity_material"],
    }
    conn = FakeConn(
        [
            ("FROM alert_key_claims", [claim]),
            ("FROM alerts WHERE", [previous]),
            ("FROM incidents i JOIN incident_alert_links", []),
        ]
    )
    processor._apply_one(
        conn, tenant, None, None, supplied_item=item, coordinated=(work_row(tenant), BASE)
    )
    assert body["lock_catalog"] == [[previous["id"]]]
    assert len(conn.matching("LOCK CONTEXTS FOR TARGETS")) == 1
    assert not conn.matching("FROM correlation_rules")
    assert not conn.matching("WITH relevant AS")
    texts = conn.texts()
    assert texts.index("LOCK CONTEXTS FOR TARGETS") < texts.index(
        next(text for text in texts if "FROM incidents i JOIN incident_alert_links" in text)
    )
    assert len([text for text in texts if text.startswith("UPDATE alerts SET")]) == 1
    assert not [text for text in texts if text.startswith("INSERT INTO alerts")]


def test_legacy_callers_still_take_the_coordinator_themselves(body):
    tenant = uuid4()
    conn = FakeConn([("FROM alert_key_claims", [])], work=work_row(tenant))
    processor._apply_one(conn, tenant, None, None, supplied_item=v1_item(tenant))
    assert len([text for text in conn.texts() if "tenant_work_state" in text]) == 2
    blocked = FakeConn(work=dict(work_row(tenant), blocked=True))
    assert processor._apply_one(blocked, tenant, None, None) is False


def test_lock_linked_incidents_keeps_context_locks_by_default():
    tenant, alert = uuid4(), uuid4()
    conn = FakeConn()
    lock_linked_incidents(conn, tenant, alert)
    assert len(conn.matching("FROM correlation_rules")) == 1
    assert len(conn.matching("WITH relevant AS")) == 1
    skipped = FakeConn()
    lock_linked_incidents(skipped, tenant, alert, contexts_locked=True)
    assert not skipped.matching("correlation_")
    assert len(skipped.statements) == 1


def test_store_alert_default_new_path_still_inserts_identity_then_alert():
    tenant = uuid4()
    current, _ = apply_source(None, v1_item(tenant))
    conn = FakeConn()
    repository.store_alert(conn, current, new=True)
    texts = conn.texts()
    assert texts[0].startswith("INSERT INTO alert_identities")
    assert texts[1].startswith("INSERT INTO alerts") and len(texts) == 2
    only_row = FakeConn()
    repository.store_alert(only_row, current, new=True, identity_inserted=True)
    assert [text[:18] for text in only_row.texts()] == ["INSERT INTO alerts"]


# Publication


def alert_row(tenant):
    current, _ = apply_source(None, v1_item(tenant))
    return dict(current, revision=1, projection_version=1)


def publish_conn(tenant, incident):
    return FakeConn(
        [
            (
                "UPDATE tenant_work_state SET change_order",
                lambda params: [
                    {"change_order": 10 + params[0], "projection_seq": 21, "now": BASE}
                ],
            ),
            ("FROM alert_notes", [{"text": "b"}, {"text": "c"}]),
            ("FROM incident_alert_links", [{"incident_id": incident}]),
            ("FROM alert_active_ownership", [{"incident_id": incident}]),
        ]
    )


@pytest.fixture
def inline(monkeypatch):
    from appchi.maintenance import runtime

    seen = []
    monkeypatch.setattr(runtime, "publish_inline_effects", lambda conn, after: seen.append(conn))
    return seen


def test_publish_folds_clock_into_counters_and_pipelines_the_rest(inline):
    tenant, incident = uuid4(), uuid4()
    after = alert_row(tenant)
    conn = publish_conn(tenant, incident)
    result = repository.publish(
        conn,
        None,
        after,
        BASE - timedelta(seconds=1),
        "source",
        semantic=True,
        original_order=5,
        maintenance_input_recorded=True,
    )
    assert set(result) == {"change_order", "projection_seq", "envelope", "event_id"}
    assert (result["change_order"], result["projection_seq"]) == (11, 21)
    envelope = json.loads(result["envelope"])
    assert envelope["event_id"] == result["event_id"]
    assert envelope["recorded_at"] == "2026-10-18T00:00:00.000000Z"
    assert envelope["change_order"] == "11" and envelope["projection_seq"] == "21"
    texts = conn.texts()
    assert not [text for text in texts if text.startswith("SELECT clock_timestamp()")]
    work = [entry for entry in conn.statements if "tenant_work_state" in entry[0]]
    assert len(work) == 1 and work[0][2] == 0
    assert "RETURNING change_order,projection_seq,clock_timestamp() AS now" in work[0][0]
    # Everything after the counters runs inside one pipeline.
    assert all(depth == 1 for _, _, depth in conn.statements[1:])
    assert len(conn.statements) == 10  # previously 11, each its own round trip
    (_, projection, _) = conn.matching("INSERT INTO projection_work")[0]
    snapshot = projection[4].obj
    assert snapshot["notes"] == ["b", "c"]
    assert snapshot["incident_ids"] == [str(incident)]
    assert snapshot["active_incident_id"] == str(incident)
    assert conn.events[-1] == "pipeline-exit" and inline == [conn]


def test_non_semantic_source_skips_history_rows(inline):
    tenant = uuid4()
    conn = publish_conn(tenant, uuid4())
    result = repository.publish(
        conn,
        None,
        alert_row(tenant),
        BASE,
        "source",
        semantic=False,
        original_order=5,
        maintenance_input_recorded=True,
    )
    assert result["change_order"] == 10
    assert not conn.matching("alert_activity") and not conn.matching("correlation_journal")


def test_manual_publication_remembers_envelope_after_the_pipeline(inline, monkeypatch):
    from appchi import alert_notifications

    tenant, actor = uuid4(), uuid4()
    after = alert_row(tenant)
    conn = publish_conn(tenant, uuid4())
    conn.answers.insert(0, ("FROM principals", [{"display_name": "Ada"}]))
    remembered = []
    monkeypatch.setattr(
        alert_notifications, "remember", lambda value: remembered.append(conn.depth)
    )
    repository.publish(
        conn,
        dict(after, message="before"),
        after,
        BASE,
        "manual-edit",
        actor=actor,
        original_order=6,
        maintenance_input_recorded=True,
    )
    assert remembered == [0]
    (principals,) = conn.matching("FROM principals")
    assert principals[2] == 0
    (_, activity, depth) = conn.matching("INSERT INTO alert_activity")[0]
    assert depth == 1 and activity[-1] == "Ada"


class RawCursor:
    def __init__(self, rows):
        self.rows, self.position = list(rows), 0

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def __next__(self):
        if self.position >= len(self.rows):
            raise StopIteration
        self.position += 1
        return self.rows[self.position - 1]


class RawConn(FakeConn):
    """psycopg-like connection: execute returns a cursor; pipeline() exists."""

    def execute(self, query, params=()):
        return RawCursor(super().execute(query, params).rows)


def test_publish_pipelines_through_budget_connection(inline):
    tenant, incident = uuid4(), uuid4()
    raw = RawConn(publish_conn(tenant, incident).answers)
    with request_budget(30):
        conn = database_module.BudgetConnection(raw)
        result = repository.publish(
            conn,
            None,
            alert_row(tenant),
            BASE,
            "source",
            original_order=5,
            maintenance_input_recorded=True,
        )
    assert result["change_order"] == 11
    pipelined = [text for text, _, depth in raw.statements if depth == 1]
    assert any(text.startswith("INSERT INTO projection_work") for text in pipelined)
    # BudgetConnection bounds statements inside the pipeline as well.
    assert raw.matching("SET LOCAL statement_timeout")
    assert raw.events.count("pipeline-enter") == 1
    snapshot = raw.matching("INSERT INTO projection_work")[0][1][4].obj
    assert snapshot["incident_ids"] == [str(incident)]
    assert inline == [conn]


def test_changed_uses_supplied_event_id_and_still_defaults_to_uuid4():
    tenant = uuid4()
    arguments = dict(
        tenant=tenant,
        alert=uuid4(),
        seq=1,
        version=1,
        snapshot={"schema_version": "v1"},
        change_order=1,
        cause="source",
        effective_at=BASE,
        recorded_at=BASE,
    )
    supplied = str(uuid4())
    assert json.loads(changed(**arguments, event_id=supplied))["event_id"] == supplied
    generated = json.loads(changed(**arguments))["event_id"]
    assert UUID(generated).version == 4
