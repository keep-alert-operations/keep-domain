"""Per-alert preparation units of work and reusable compiled CEL programs.

A recording database stands in for PostgreSQL and a counting stand-in replaces
the compiler child and native runtime, so these checks need neither service.
"""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
from threading import Thread
from uuid import uuid4

import pytest

import appchi.cel.compiler as compiler
from appchi.cel.compiler import COST_MODEL, PROFILE
from appchi.correlation import repository
from appchi.correlation import runtime as correlation
from appchi.maintenance import runtime as maintenance
from appchi.serialization import wire
from appchi.shared.errors import AppError

NOW = datetime(2026, 10, 18, 12, tzinfo=UTC)
RELEASE = NOW - timedelta(days=1)
SEGMENT_CEL = 'alert.message == "maintenance"'
CONDITION_CEL = 'alert.severity == "critical"'
QUALIFIED = {
    "qualified": True,
    "maintenance_max_work": 100,
    "maintenance_max_inputs": 10,
    "maintenance_max_segments": 5,
    "correlation": {"cost_model": COST_MODEL, **{name: 1000 for name in repository.BUDGETS}},
}


class Native:
    """Counts checked compilations (child processes) and native handle builds."""

    def __init__(self):
        self.compiled, self.environments = [], 0

    def compile(self, source, rule):
        self.compiled.append((source, rule))
        ir = compiler.IR("literal", "bool", True)
        return ir, ("message",), (), b"checked:" + source.encode(), 1, "true"

    def environment(self, fields, bound_count):
        self.environments += 1
        return self

    def deserialize(self, checked):
        return self

    def eval(self, data):
        return self

    def value(self):
        return True


class Tenant:
    """Rows for one tenant: one checkpointed alert, one segment and one rule."""

    def __init__(self, *, maintenance=True, correlation=True, supports=()):
        self.id, self.alert = uuid4(), uuid4()
        self.maintenance, self.correlation, self.supports = maintenance, correlation, supports
        self.rule, self.condition = uuid4(), uuid4()
        self.continuation = {
            "version": 2,
            "generation": 3,
            "source_release_since": wire(RELEASE),
            "last_at": (NOW - timedelta(hours=1)).isoformat(),
            "causes": [],
        }
        self.segment = {
            "id": uuid4(),
            "window_id": uuid4(),
            "expression_revision": 1,
            "activation_at": NOW - timedelta(hours=2),
            "activation_order": 1,
            "activation_id": uuid4(),
            "start_at": NOW - timedelta(hours=2),
            "end_at": NOW + timedelta(hours=2),
            "cel": SEGMENT_CEL,
            "profile": PROFILE,
            "cel_digest": hashlib.sha256(SEGMENT_CEL.encode()).hexdigest(),
            "deactivation_at": None,
            "deactivation_order": None,
            "deactivation_id": None,
            "end_revisions": [],
        }

    def respond(self, text, params):
        if text.startswith(("SET TRANSACTION", "SELECT set_config")):
            return []
        if "AS maintenance_ready" in text:
            return [
                {
                    "maintenance_generation": 3,
                    "prepared_at": NOW,
                    "source_release_since": RELEASE,
                    "maintenance_ready": self.maintenance,
                    "correlation_enabled": self.correlation,
                }
            ]
        if "FROM maintenance_alert_checkpoints" in text:
            # Every alert has a current checkpoint, so no replay is prepared.
            return [
                {"alert_id": alert, "continuation": dict(self.continuation)}
                for alert in (self.alert, *self.supports)
                if str(alert) in {str(value) for value in params[1]}
            ]
        if "FROM maintenance_segments" in text:
            return [dict(self.segment)]
        if "FROM correlation_rules" in text and "ORDER BY created_at,id" in text:
            return [self.rule_row()]
        if "FROM correlation_conditions" in text:
            return [
                {
                    "tenant_id": self.id,
                    "rule_id": self.rule,
                    "id": self.condition,
                    "position": 0,
                    "label": "Critical",
                    "cel": CONDITION_CEL,
                }
            ]
        if "FROM correlation_evidence" in text:
            return [{"alert_id": value} for value in self.supports]
        raise AssertionError(f"Unexpected preparation statement: {text}")

    def rule_row(self):
        return {
            "id": self.rule,
            "tenant_id": self.id,
            "revision": 1,
            "created_at": NOW - timedelta(days=2),
            "enabled": True,
            "kafka_schema_blocked": False,
            "evaluation_cost": 1,
            "name": "Critical",
            "description": "",
            "severity": "critical",
            "window_minutes": 5,
            "group_by": [],
        }


class Database:
    """Records each unit of work (transaction) and its statements."""

    def __init__(self, tenant):
        self.tenant, self.transactions = tenant, []

    @contextmanager
    def transaction(self, tenant_id=None):
        statements = []
        self.transactions.append(statements)
        yield Connection(self.tenant, statements)

    def reads(self, table):
        return sum(table in text for statements in self.transactions for text in statements)


class Connection:
    def __init__(self, tenant, statements):
        self.tenant, self.statements = tenant, statements

    def execute(self, sql, params=()):
        text = " ".join(sql.split())
        self.statements.append(text)
        return Result(self.tenant.respond(text, params))


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)

    def __iter__(self):
        return iter(self.rows)


@pytest.fixture
def native(monkeypatch):
    stand_in = Native()
    monkeypatch.setattr(compiler, "_compile_native", stand_in.compile)
    monkeypatch.setattr(compiler, "environment", stand_in.environment)
    monkeypatch.setattr(compiler, "_checked_cache", compiler._CompileCache())
    monkeypatch.setattr(compiler, "_reusable", compiler._ThreadPrograms())
    return stand_in


def source_preparation(database, tenant, *, gate_ready=True):
    return maintenance.prepare_for_tenant(
        database,
        tenant.id,
        QUALIFIED,
        gate_ready=gate_ready,
        alert_id=tenant.alert,
        effective_at=NOW,
    )


@pytest.mark.parametrize("gate_ready", [True, None])
def test_inline_source_preparation_uses_two_snapshots(native, gate_ready):
    tenant = Tenant()
    database = Database(tenant)
    catalog = source_preparation(database, tenant, gate_ready=gate_ready)
    assert catalog.inline_correlation is not None and catalog.require_preparation
    # Catalog snapshot (gates, correlation enablement, checkpoints, segments),
    # then the correlation snapshot. Formerly 4, or 5 without a supplied gate.
    assert len(database.transactions) == 2
    assert database.reads("FROM capability_gates") == 1
    assert database.reads("FROM maintenance_alert_checkpoints") == 1
    # Formerly one id query plus two statements per rule.
    assert database.reads("FROM correlation_rules WHERE tenant_id=%s AND id=%s") == 0
    assert database.reads("FROM correlation_conditions") == 1


def test_disabled_correlation_needs_only_the_catalog_snapshot(native):
    tenant = Tenant(correlation=False)
    database = Database(tenant)
    catalog = source_preparation(database, tenant)
    assert catalog.inline_requested and catalog.inline_correlation is None
    assert len(database.transactions) == 1


def test_closed_gate_ends_the_snapshot_before_catalog_reads(native):
    tenant = Tenant(maintenance=False)
    database = Database(tenant)
    # A closed gate is decided before the capacity profile is required.
    assert maintenance.prepare_for_tenant(database, tenant.id, None, alert_id=tenant.alert) is None
    assert len(database.transactions) == 1
    assert database.reads("FROM maintenance_alert_checkpoints") == 0
    assert database.reads("FROM maintenance_segments") == 0
    assert native.compiled == []


def test_supplied_closed_gate_reads_nothing(native):
    database = Database(Tenant())
    assert maintenance.prepare_for_tenant(database, uuid4(), None, gate_ready=False) is None
    assert database.transactions == []
    with pytest.raises(ValueError):
        maintenance.prepare_for_tenant(database, uuid4(), None, gate_ready=1)


def test_decision_attachments_add_one_catalog_snapshot(native):
    tenant = Tenant(supports=(uuid4(),))
    database = Database(tenant)
    catalog = source_preparation(database, tenant)
    assert catalog.inline_correlation is not None
    # The nested attachment catalog folds its gate read too (formerly 7 in all).
    assert len(database.transactions) == 3


def test_correlation_consumer_preparation_uses_two_snapshots(native):
    tenant = Tenant()
    database = Database(tenant)
    prepared = correlation.prepare_tenant(database, tenant.id, QUALIFIED, alert_ids=(tenant.alert,))
    assert prepared.maintenance is not None
    assert [row["id"] for row in prepared.rows] == [tenant.rule]
    # Correlation snapshot plus one gated catalog snapshot (formerly 4).
    assert len(database.transactions) == 2


def test_repeated_alerts_reuse_programs_and_native_handles(native):
    tenant = Tenant()
    first = source_preparation(Database(tenant), tenant)
    second = source_preparation(Database(tenant), tenant)
    program = first.segments[0].program
    assert second.segments[0].program is program
    condition = first.inline_correlation.prepared.programs[tenant.rule][str(tenant.condition)]
    assert second.inline_correlation.prepared.programs[tenant.rule][str(tenant.condition)] is (
        condition
    )
    assert sorted(native.compiled) == [(SEGMENT_CEL, True), (CONDITION_CEL, True)]
    # Native handles are built during preparation, before any writer lock.
    assert native.environments == 2
    for _ in range(3):
        assert program.evaluate({"message": "maintenance"}, NOW) is True
    assert native.environments == 2


def test_reused_programs_are_per_thread_but_share_checked_data(native):
    program = compiler.compile_expression(SEGMENT_CEL, rule=True, reuse=True)
    assert compiler.compile_expression(SEGMENT_CEL, rule=True, reuse=True) is program
    assert compiler.compile_expression(SEGMENT_CEL, rule=False, reuse=True) is not program
    other = []
    thread = Thread(
        target=lambda: other.append(compiler.compile_expression(SEGMENT_CEL, rule=True, reuse=True))
    )
    thread.start()
    thread.join()
    assert other[0] is not program and other[0].checked is program.checked
    assert native.compiled == [(SEGMENT_CEL, True), (SEGMENT_CEL, False)]
    assert native.environments == 3
    # Fresh instances keep their own handles, as before.
    fresh = compiler.compile_expression(SEGMENT_CEL, rule=True)
    assert fresh is not program and fresh._program is None


def test_reusable_lru_evicts_oldest_and_never_caches_failed_warmup(native, monkeypatch):
    monkeypatch.setattr(compiler, "_reusable", compiler._ThreadPrograms(capacity=2))
    a = compiler.compile_expression("a", reuse=True)
    compiler.compile_expression("b", reuse=True)
    assert compiler.compile_expression("a", reuse=True) is a
    compiler.compile_expression("c", reuse=True)
    assert compiler.compile_expression("a", reuse=True) is a
    assert native.environments == 3
    compiler.compile_expression("b", reuse=True)
    assert native.environments == 4

    def unavailable(fields, bound_count):
        raise RuntimeError("native runtime missing")

    monkeypatch.setattr(compiler, "environment", unavailable)
    with pytest.raises(compiler.CELUnavailableError):
        compiler.compile_expression("d", reuse=True)
    monkeypatch.setattr(compiler, "environment", native.environment)
    assert compiler.compile_expression("d", reuse=True)._program is native


def test_checked_cache_retains_beyond_the_pending_bound(native):
    cache = compiler._CompileCache(capacity=300)
    assert cache.max_pending == compiler.MAX_PENDING_COMPILES == 256
    assert compiler._CompileCache(capacity=2).max_pending == 2
    for index in range(300):
        cache.get(index, lambda index=index: native.compile(str(index), True))
    assert cache.get(0, lambda: pytest.fail("Retained key compiled again"))[3] == b"checked:0"
    assert len(native.compiled) == 300


@pytest.mark.parametrize(("value", "expected"), [(None, 4096), ("1", 1), (" 65536 ", 65536)])
def test_cache_entries_default_and_override(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("APPCHI_CEL_CACHE_ENTRIES", raising=False)
    else:
        monkeypatch.setenv("APPCHI_CEL_CACHE_ENTRIES", value)
    assert compiler._cache_entries() == expected


@pytest.mark.parametrize("value", ["0", "65537", "-4", "many", ""])
def test_cache_entries_rejects_unbounded_values(monkeypatch, value):
    monkeypatch.setenv("APPCHI_CEL_CACHE_ENTRIES", value)
    with pytest.raises(ValueError, match="APPCHI_CEL_CACHE_ENTRIES"):
        compiler._cache_entries()


def test_batched_rule_conditions_match_get_rule(native):
    tenant = Tenant()
    statements = []
    connection = Connection(tenant, statements)

    class Single(Connection):
        def execute(self, sql, params=()):
            if "AND id=%s" in sql:
                self.statements.append(sql)
                return Result([tenant.rule_row()])
            return super().execute(sql, params)

    single = repository.get_rule(Single(tenant, []), tenant.id, tenant.rule)
    batched = repository.with_conditions(connection, tenant.id, [tenant.rule_row()])
    assert batched == (single,)
    assert len(statements) == 1
    assert repository.with_conditions(connection, tenant.id, []) == ()
    assert len(statements) == 1


class WorkerTenant(Tenant):
    """Answers a worker turn up to its evidence load; health changed after preparation."""

    def __init__(self, *, revision=1):
        super().__init__()
        self.revision = revision

    def respond(self, text, params):
        if text.startswith("SELECT ready FROM capability_gates"):
            return [{"ready": True}]
        if "FROM tenant_work_state" in text:
            return [{"tenant_id": self.id}]
        if "UPDATE tenant_work_state" in text:
            return [{"now": NOW, "admission_order": 1}]
        if text.endswith(("ORDER BY id FOR UPDATE", "FOR UPDATE OF c")):
            return []  # lock_contexts
        if text.startswith("SELECT id,revision,health,blocked_reason FROM correlation_rules"):
            return [
                {
                    "id": self.rule,
                    "revision": self.revision,
                    "health": "blocked",
                    "blocked_reason": "condition_evaluation_failed",
                }
            ]
        if "FROM correlation_consumer_state" in text:
            return [{"kafka_sequence": 0, "change_order": 0}]
        return super().respond(text, params)

    def rule_row(self):
        return dict(super().rule_row(), health="healthy", blocked_reason=None)


class Loaded(Exception):
    pass


def test_worker_turn_refreshes_health_without_reloading_rules(native, monkeypatch):
    tenant = WorkerTenant()
    prepared = correlation.prepare_tenant(Database(tenant), tenant.id, QUALIFIED)
    seen = []

    def load(conn, current, *args, **kwargs):
        seen.append(current)
        raise Loaded

    monkeypatch.setattr(correlation, "_load", load)
    database = Database(tenant)
    with pytest.raises(Loaded):
        correlation.worker_turn(database, tenant.id, QUALIFIED, prepared_input=prepared, kafka=True)
    # A rule blocked by an earlier turn stays blocked, as get_rule reported it.
    (row,) = seen[0].rows
    assert (row["health"], row["blocked_reason"]) == ("blocked", "condition_evaluation_failed")
    assert {k: v for k, v in row.items() if k not in {"health", "blocked_reason"}} == {
        k: v for k, v in prepared.rows[0].items() if k not in {"health", "blocked_reason"}
    }
    # The reusable prepared input is not mutated.
    assert (prepared.rows[0]["health"], prepared.rows[0]["blocked_reason"]) == ("healthy", None)
    # Health rides on the revision check; formerly two statements per enabled rule.
    assert database.reads("FROM correlation_rules WHERE tenant_id=%s AND id=%s") == 0
    assert database.reads("FROM correlation_conditions") == 0
    assert database.reads("ORDER BY created_at,id") == 1


def test_worker_turn_still_rejects_a_changed_revision(native, monkeypatch):
    tenant = WorkerTenant(revision=2)
    prepared = correlation.prepare_tenant(Database(tenant), tenant.id, QUALIFIED)
    monkeypatch.setattr(correlation, "_load", lambda *args, **kwargs: pytest.fail("loaded"))
    with pytest.raises(AppError) as raised:
        correlation.worker_turn(
            Database(tenant), tenant.id, QUALIFIED, prepared_input=prepared, kafka=True
        )
    assert raised.value.code == "correlation_compiled_revision_changed"
