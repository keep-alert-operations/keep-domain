"""Changed-event offsets commit in batches, after durable PostgreSQL state."""

from collections import deque
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from appchi import kafka_changed
from appchi.kafka_changed import ChangedConsumer, PartitionRetries


def message(partition, offset):
    return SimpleNamespace(
        topic=lambda: "changed",
        partition=lambda: partition,
        offset=lambda: offset,
        error=lambda: None,
    )


class Database:
    def __init__(self):
        self.transactions = []

    @contextmanager
    def transaction(self, *args, **kwargs):
        statements = []
        self.transactions.append(statements)
        yield SimpleNamespace(execute=lambda sql, params=None: statements.append((sql, params)))

    def positions(self):
        return [
            params
            for statements in self.transactions
            for sql, params in statements
            if "kafka_consumer_positions" in sql
        ]


@pytest.fixture
def clock(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(kafka_changed, "monotonic", lambda: now[0])
    return now


def consumer(*batches, commit_every=100, commit_interval=0.1, handler=None):
    worker = ChangedConsumer.__new__(ChangedConsumer)
    worker.db, worker.settings, worker.profile, worker.role = Database(), None, None, "correlation"
    worker.handler, worker.batch_handler = handler or Mock(), None
    worker.batch_size, worker.pending, worker.closing = 50, deque(), False
    worker.commit_every, worker.commit_interval = commit_every, commit_interval
    worker.uncommitted, worker.uncommitted_count, worker.uncommitted_since = {}, 0, None
    worker.client = Mock()
    worker.client.consume.side_effect = [*batches, *([[]] * 20)]
    worker.client.poll.return_value = None
    worker.retries = PartitionRetries(worker.client)
    return worker


def committed(worker):
    return [
        [(p.topic, p.partition, p.offset) for p in call.kwargs["offsets"]]
        for call in worker.client.commit.call_args_list
    ]


def test_each_handled_event_costs_no_commit_or_position_transaction_until_the_batch_fills(clock):
    worker = consumer([message(0, i) for i in range(3)], commit_every=3)
    assert worker.turn() == 1
    assert worker.turn() == 1
    worker.client.commit.assert_not_called()
    assert worker.db.transactions == []
    assert worker.turn() == 1
    assert committed(worker) == [[("changed", 0, 3)]]
    assert worker.client.commit.call_args.kwargs["asynchronous"] is False
    # One positions statement in one transaction covers the whole batch.
    assert len(worker.db.transactions) == 1
    assert worker.db.positions() == [("correlation", ["changed"], [0], [3])]
    assert worker.uncommitted == {}


def test_partial_batch_commits_once_the_interval_elapses_even_when_idle(clock):
    # Binary fractions keep the deadline arithmetic exact.
    worker = consumer([message(0, 7)], [message(1, 2)], commit_interval=0.125)
    assert worker.turn() == 1
    clock[0] += 0.0625
    assert worker.turn() == 1
    worker.client.commit.assert_not_called()
    clock[0] += 0.03125
    assert worker.turn() == 0
    worker.client.commit.assert_not_called()
    clock[0] += 0.03125
    assert worker.turn() == 0
    assert committed(worker) == [[("changed", 0, 8), ("changed", 1, 3)]]
    assert worker.db.positions() == [("correlation", ["changed"] * 2, [0, 1], [8, 3])]
    # The interval restarts with the next handled input, not the last flush.
    clock[0] += 1
    assert worker.turn() == 0
    assert worker.client.commit.call_count == 1


def test_offsets_are_recorded_only_after_the_handler_transaction_returns(clock):
    events = []
    worker = consumer([message(0, 1)], commit_every=1)
    worker.handler.side_effect = lambda *_: events.append("postgres")
    worker.client.commit.side_effect = lambda **_: events.append("kafka")
    assert worker.turn() == 1
    assert events == ["postgres", "kafka"]


def test_revoke_commits_owned_progress_and_forgets_revoked_partitions(clock):
    worker = consumer([message(0, 4), message(1, 9)])
    assert worker.turn() == 1
    assert worker.turn() == 1
    worker._revoke(worker.client, [SimpleNamespace(topic="changed", partition=0)])
    assert committed(worker) == [[("changed", 0, 5), ("changed", 1, 10)]]
    assert worker.uncommitted == {}
    assert len(worker.db.positions()) == 1


def test_failed_revoke_commit_never_carries_offsets_into_a_later_assignment(clock):
    worker = consumer([message(0, 4), message(1, 9)])
    worker.client.commit.side_effect = RuntimeError("rebalance")
    assert worker.turn() == 1
    assert worker.turn() == 1
    worker._revoke(worker.client, [SimpleNamespace(topic="changed", partition=0)])
    # Partition 1 is still owned (cooperative revocation) and may commit later.
    assert list(worker.uncommitted) == [("changed", 1)]
    assert worker.db.positions() == []


def test_lost_partitions_drop_progress_without_committing_a_fenced_generation(clock):
    worker = consumer([message(0, 4), message(1, 9)])
    assert worker.turn() == 1
    assert worker.turn() == 1
    worker.pending.append([message(0, 5)])
    worker._lost(
        worker.client,
        [
            SimpleNamespace(topic="changed", partition=0),
            SimpleNamespace(topic="changed", partition=1),
        ],
    )
    worker.client.commit.assert_not_called()
    assert worker.uncommitted == {} and worker.uncommitted_since is None
    assert not worker.pending
    worker.flush()
    worker.client.commit.assert_not_called()


def test_close_flushes_before_closing_and_closes_when_the_commit_fails(clock):
    worker = consumer([message(0, 4)])
    assert worker.turn() == 1
    order = []
    worker.client.commit.side_effect = lambda **_: order.append("commit")
    worker.client.close.side_effect = lambda: order.append("close")
    worker.close()
    assert order == ["commit", "close"]
    assert worker.closing

    failing = consumer([message(0, 4)])
    assert failing.turn() == 1
    failing.client.commit.side_effect = RuntimeError("broker down")
    failing.close()
    failing.client.close.assert_called_once()
    assert failing.db.positions() == []


def test_handler_failure_flushes_the_prefix_but_never_the_failed_offset(clock):
    def handler(db, settings, profile, item):
        if item.offset() == 5:
            raise ValueError("poison")

    worker = consumer([message(0, 4), message(0, 5), message(1, 2)], handler=handler)
    assert worker.turn() == 1
    assert worker.turn() == 1
    worker.client.commit.assert_not_called()
    assert worker.turn() == 0
    # Committed offsets are the next inputs: partition 0 stays at the failure.
    assert committed(worker) == [[("changed", 0, 5), ("changed", 1, 3)]]
    assert worker.client.seek.call_args.args[0].offset == 5
    assert ("changed", 0) in worker.retries.failed
