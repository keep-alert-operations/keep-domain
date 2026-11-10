"""Concurrent cold compilation shares checked data, never native handles."""

from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from threading import Event

import pytest

import keep.cel.compiler as compiler


def test_identical_cold_requests_compile_once_without_blocking_unrelated_cache_hits(monkeypatch):
    cache = compiler._CompileCache()
    monkeypatch.setattr(compiler, "_checked_cache", cache)
    started, release = Event(), Event()
    calls = []

    def native(source, rule):
        calls.append((source, rule))
        if source == "true":
            started.set()
            assert release.wait(3)
        return compiler.IR("literal", "bool", source == "true"), (), (), b"checked", 1, source

    monkeypatch.setattr(compiler, "_compile_native", native)
    compiler.compile_expression("false")
    with ThreadPoolExecutor(max_workers=12) as pool:
        cold = [pool.submit(compiler.compile_expression, "true") for _ in range(10)]
        assert started.wait(1)
        try:
            hit = pool.submit(compiler.compile_expression, "false").result(timeout=1)
            assert hit.source == "false"
        finally:
            release.set()
        expressions = [task.result(timeout=2) for task in cold]
    assert calls == [("false", False), ("true", False)]
    assert len({id(value) for value in expressions}) == len(expressions)
    object.__setattr__(expressions[0], "_program", object())
    assert all(value._program is None for value in expressions[1:])


def test_failed_compile_can_retry_and_cache_preserves_lru_capacity():
    cache = compiler._CompileCache(capacity=2)
    calls = []

    def fail():
        raise compiler.CELUnavailableError("temporary compiler failure")

    with pytest.raises(compiler.CELUnavailableError):
        cache.get("a", fail)

    def read(key):
        return cache.get(key, lambda: calls.append(key) or key)

    assert read("a") == "a"
    read("b")
    read("a")
    read("c")
    read("a")
    read("b")
    assert calls == ["a", "b", "c", "b"]


def test_pending_bookkeeping_is_bounded_without_blocking_existing_hits():
    cache = compiler._CompileCache(capacity=2)
    started = {key: Event() for key in ("a", "b", "c")}
    release = Event()
    cache.get("warm", lambda: "warm")

    def read(key):
        def compile_one():
            started[key].set()
            assert release.wait(3)
            return key

        return cache.get(key, compile_one)

    with ThreadPoolExecutor(max_workers=4) as pool:
        first = pool.submit(read, "a")
        second = pool.submit(read, "b")
        assert started["a"].wait(1) and started["b"].wait(1)
        third = pool.submit(read, "c")
        try:
            assert pool.submit(cache.get, "warm", lambda: None).result(timeout=1) == "warm"
            assert not started["c"].is_set()
        finally:
            release.set()
        assert [task.result(timeout=2) for task in (first, second, third)] == ["a", "b", "c"]


@pytest.mark.parametrize("key", ["same", "other"])
def test_expired_http_waiter_releases_thread_without_cancelling_owner(key):
    from keep.request_budget import request_budget
    from keep.shared.errors import AppError

    cache = compiler._CompileCache(capacity=1)
    started, release = Event(), Event()

    def compile_one():
        started.set()
        assert release.wait(3)
        return "checked"

    def waiting_request():
        with request_budget(0.02):
            return cache.get(key, lambda: "unexpected second compile")

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(cache.get, "same", compile_one)
        assert started.wait(1)
        try:
            waiter = pool.submit(waiting_request)
            with pytest.raises(AppError, match="request_timeout"):
                waiter.result(timeout=1)
            assert not owner.done()
        finally:
            release.set()
        assert owner.result(timeout=2) == "checked"
    assert cache.get("same", lambda: None) == "checked"


@pytest.mark.parametrize("completion", ["checked", "expired"])
def test_early_follower_wakeup_reuses_original_deadline(monkeypatch, completion):
    import keep.request_budget as budget
    from keep.shared.errors import AppError

    clock = [0.0]
    monkeypatch.setattr(budget, "monotonic", lambda: clock[0])
    timeouts = []

    class EarlyWake(Future):
        def result(self, timeout=None):
            timeouts.append(timeout)
            if len(timeouts) == 1:
                clock[0] = 0.25
                raise TimeoutError("early wakeup")
            if completion == "expired":
                clock[0] = 1.0
                raise TimeoutError("deadline wakeup")
            self.set_result("checked")
            return super().result(timeout)

    cache = compiler._CompileCache()
    owner = EarlyWake()
    cache.pending["same"] = owner
    with budget.request_budget(1):
        if completion == "expired":
            with pytest.raises(AppError, match="request_timeout"):
                cache.get("same", lambda: pytest.fail("Follower compiled independently"))
            assert not owner.done()
        else:
            assert cache.get("same", lambda: None) == "checked"
    assert timeouts == [1.0, 0.75]
    assert not owner.cancelled()


@pytest.mark.parametrize("cancelled", [False, True])
def test_follower_preserves_owner_timeout_error_and_cancellation(cancelled):
    cache = compiler._CompileCache()
    owner = Future()
    cache.pending["same"] = owner
    error = TimeoutError("owner timed out")
    if cancelled:
        owner.cancel()
    else:
        owner.set_exception(error)
    with pytest.raises(CancelledError if cancelled else TimeoutError) as raised:
        cache.get("same", lambda: pytest.fail("Follower compiled independently"))
    if not cancelled:
        assert raised.value is error
