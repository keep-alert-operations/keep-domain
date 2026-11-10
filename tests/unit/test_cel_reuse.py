"""Reused CEL programs avoid native rebuilds; undersized caches are reported.

A counting stand-in replaces the compiler child and native runtime, so these
checks need neither the native wheel nor a database.
"""

import logging
from threading import Thread

import pytest

import keep.cel.compiler as compiler
from keep.correlation import runtime as correlation
from test_preparation_transactions import (
    CONDITION_CEL,
    NOW,
    CONFIGURED,
    SEGMENT_CEL,
    Database,
    Native,
    Tenant,
)


@pytest.fixture
def counted(monkeypatch):
    stand_in = Native()
    monkeypatch.setattr(compiler, "_compile_native", stand_in.compile)
    monkeypatch.setattr(compiler, "environment", stand_in.environment)
    monkeypatch.setattr(compiler, "_checked_cache", compiler._CompileCache())
    monkeypatch.setattr(compiler, "_reusable", compiler._ThreadPrograms())
    return stand_in


def test_repeated_correlation_turns_never_recompile_or_rebuild(counted):
    tenants = [Tenant(), Tenant()]
    prepared = [
        correlation.prepare_tenant(
            Database(tenant), tenant.id, CONFIGURED, alert_ids=(tenant.alert,)
        )
        for _ in range(5)
        for tenant in tenants
    ]
    # One checked compile (child process) and one native handle per distinct
    # expression, however many turns and tenants use it.
    assert sorted(counted.compiled) == [(SEGMENT_CEL, True), (CONDITION_CEL, True)]
    assert counted.environments == 2
    programs = {
        id(turn.programs[tenant.rule][str(tenant.condition)])
        for turn, tenant in zip(prepared, tenants * 5)
    }
    assert len(programs) == 1
    program = prepared[0].programs[tenants[0].rule][str(tenants[0].condition)]
    for _ in range(10):
        assert program.evaluate({"message": "x"}, NOW) is True
    assert counted.environments == 2


def test_fresh_instances_share_checked_data_but_rebuild_handles(counted):
    for _ in range(3):
        program = compiler.compile_expression(CONDITION_CEL, rule=True)
        assert program.evaluate({"message": "x"}, NOW) is True
    # Request handlers keep this path: no further child, one handle each.
    assert counted.compiled == [(CONDITION_CEL, True)]
    assert counted.environments == 3


def test_checked_evictions_warn_once_per_interval_without_source(counted, caplog):
    cache = compiler._CompileCache(capacity=1)
    private = ["synthetic-private-a", "synthetic-private-b", "synthetic-private-c"]
    with caplog.at_level(logging.WARNING, logger=compiler.__name__):
        for source in private:
            cache.get(source, lambda source=source: counted.compile(source, True))
        cache.get(private[-1], lambda: pytest.fail("Retained key compiled again"))
    assert cache.evictions.count == 2
    records = [record for record in caplog.records if record.name == compiler.__name__]
    assert [record.getMessage() for record in records] == [
        "cel_cache_evicting cache=checked capacity=1 evictions=1 setting=KEEP_CEL_CACHE_ENTRIES"
    ]
    assert "synthetic-private" not in caplog.text


def test_program_evictions_are_counted_across_threads(counted, monkeypatch):
    evictions = compiler._Evictions("programs")
    monkeypatch.setattr(compiler, "_reusable", compiler._ThreadPrograms(1, evictions))

    def turn():
        compiler.compile_expression("a", reuse=True)
        compiler.compile_expression("b", reuse=True)

    turn()
    thread = Thread(target=turn)
    thread.start()
    thread.join()
    assert evictions.count == 2
    # The interval elapsed: the next eviction is reported again with the total.
    evictions.next_log = 0.0
    compiler.compile_expression("a", reuse=True)
    assert evictions.count == 3
