"""Several partitions' pending groups share one handler call; offsets stay per partition."""

from collections import deque
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from appchi import kafka_changed
from appchi.kafka_changed import MAX_BATCH, ChangedConsumer, PartitionRetries


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


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(kafka_changed, "monotonic", lambda: now[0])
    return now


def consumer(*batches, groups_handler, batch_handler=None, handler=None, batch_size=MAX_BATCH):
    worker = ChangedConsumer.__new__(ChangedConsumer)
    worker.db, worker.settings, worker.profile, worker.role = Database(), None, None, "indexer"
    worker.handler = handler or Mock()
    worker.batch_handler = batch_handler or Mock(side_effect=lambda db, s, p, group: len(group))
    worker.groups_handler = groups_handler
    worker.batch_size, worker.pending, worker.closing = batch_size, deque(), False
    # Commit after every handled turn so each turn's offsets are observable.
    worker.commit_every, worker.commit_interval = 1, 0.1
    worker.uncommitted, worker.uncommitted_count, worker.uncommitted_since = {}, 0, None
    worker.client = Mock()
    worker.client.consume.side_effect = [*batches, *([[]] * 20)]
    worker.client.poll.return_value = None
    worker.retries = PartitionRetries(worker.client)
    return worker


def committed(worker):
    return [
        sorted((p.partition, p.offset) for p in call.kwargs["offsets"])
        for call in worker.client.commit.call_args_list
    ]


def offsets(groups):
    return [[(m.partition(), m.offset()) for m in group] for group in groups]


def interleaved(partitions, per_partition):
    return [message(p, o) for o in range(per_partition) for p in range(partitions)]


def test_every_busy_partition_shares_one_handler_call_then_commits_per_partition():
    events = []

    def groups(db, settings, profile, prefixes):
        events.append(("bulk", offsets(prefixes)))
        return [len(prefix) for prefix in prefixes]

    worker = consumer(interleaved(3, 4), groups_handler=groups)
    worker.client.commit.side_effect = lambda **kwargs: events.append(("commit",))
    assert worker.turn() == 12
    # One call (one bulk, one refresh wait) holds every partition in offset order.
    assert events == [
        ("bulk", [[(p, o) for o in range(4)] for p in range(3)]),
        ("commit",),
    ]
    assert committed(worker) == [[(0, 4), (1, 4), (2, 4)]]
    worker.batch_handler.assert_not_called()
    assert not worker.pending


def test_each_partition_advances_only_by_its_own_covered_prefix():
    calls = []

    def groups(db, settings, profile, prefixes):
        calls.append(offsets(prefixes))
        return [2, 0, 3] if len(calls) == 1 else [len(prefix) for prefix in prefixes]

    worker = consumer(interleaved(3, 3), groups_handler=groups)
    assert worker.turn() == 5
    # Partition 1 reached nothing, so its offset is untouched.
    assert committed(worker) == [[(0, 2), (2, 3)]]
    worker.batch_handler.assert_not_called()
    # The unreached partition is now the head; partition 0's remainder follows.
    assert offsets(worker.pending) == [[(1, 0), (1, 1), (1, 2)], [(0, 2)]]
    assert worker.turn() == 4
    assert calls[1] == [[(1, 0), (1, 1), (1, 2)], [(0, 2)]]
    assert committed(worker)[-1] == [(0, 3), (1, 3)]


def test_failed_bulk_commits_nothing_and_the_head_partition_runs_alone():
    events = []

    def groups(db, settings, profile, prefixes):
        events.append("bulk")
        # A partially failed bulk raises after some items may be indexed.
        raise RuntimeError("bulk item failed")

    def batch(db, settings, profile, group):
        events.append(("head", offsets([group])))
        return len(group)

    worker = consumer(
        interleaved(2, 2), groups_handler=groups, batch_handler=Mock(side_effect=batch)
    )
    worker.client.commit.side_effect = lambda **kwargs: events.append("commit")
    assert worker.turn() == 2
    # Nothing from the failed bulk is committed; only the separately handled head.
    assert events == ["bulk", ("head", [[(0, 0), (0, 1)]]), "commit"]
    assert committed(worker) == [[(0, 2)]]
    assert offsets(worker.pending) == [[(1, 0), (1, 1)]]


def test_an_unreached_head_is_isolated_and_fenced_alone_after_others_commit():
    def groups(db, settings, profile, prefixes):
        return [0] + [len(prefix) for prefix in prefixes[1:]]

    batch = Mock(side_effect=RuntimeError("authority missing"))
    handler = Mock(side_effect=RuntimeError("authority missing"))
    worker = consumer(
        interleaved(2, 2), groups_handler=groups, batch_handler=batch, handler=handler
    )
    assert worker.turn() == 2
    # The healthy partition's offset committed; the head failed alone and is fenced.
    assert committed(worker) == [[(1, 2)]]
    assert ("changed", 0) in worker.retries.failed
    point = worker.client.seek.call_args.args[0]
    assert (point.partition, point.offset) == (0, 0)
    assert offsets([batch.call_args.args[3]]) == [[(0, 0), (0, 1)]]
    assert not worker.pending


def test_invalid_progress_from_the_shared_call_advances_nothing():
    worker = consumer(interleaved(2, 1), groups_handler=Mock(return_value=[1, 2]))
    assert worker.turn() == 1
    # Count 2 exceeds the one-input prefix: only the separately handled head commits.
    assert committed(worker) == [[(0, 1)]]


def test_lost_partitions_drop_pending_groups_and_uncommitted_progress():
    seen = []

    def groups(db, settings, profile, prefixes):
        seen.append(offsets(prefixes))
        return [len(prefix) for prefix in prefixes]

    worker = consumer(interleaved(3, 2), groups_handler=groups)
    worker.commit_every = 100
    worker.pending.extend([[message(p, o) for o in range(2)] for p in range(3)])
    worker.client.consume.side_effect = [[]] * 5
    worker._lost(worker.client, [SimpleNamespace(topic="changed", partition=1)])
    assert [g[0].partition() for g in worker.pending] == [0, 2]
    assert worker.turn() == 4
    assert seen == [[[(0, 0), (0, 1)], [(2, 0), (2, 1)]]]
    # Progress handled before a loss is dropped without a commit.
    worker._lost(worker.client, [SimpleNamespace(topic="changed", partition=0)])
    assert worker.uncommitted.keys() == {("changed", 2)}
    worker.client.commit.assert_not_called()
    worker.flush()
    assert committed(worker) == [[(2, 2)]]


def test_only_the_first_group_of_a_partition_joins_and_the_call_stays_within_batch_size():
    seen = []

    def groups(db, settings, profile, prefixes):
        seen.append(offsets(prefixes))
        return [len(prefix) for prefix in prefixes]

    worker = consumer(groups_handler=groups, batch_size=5)
    worker.client.consume.side_effect = [[]] * 5
    worker.pending.extend(
        [
            [message(0, o) for o in range(3)],
            [message(0, o) for o in range(3, 5)],
            [message(1, o) for o in range(4)],
            [message(2, 0)],
        ]
    )
    assert worker.turn() == 5
    # Partition 0's second group waits; partition 1 contributes a 2-input prefix;
    # partition 2 does not fit.
    assert seen == [[[(0, 0), (0, 1), (0, 2)], [(1, 0), (1, 1)]]]
    assert committed(worker) == [[(0, 3), (1, 2)]]
    assert offsets(worker.pending) == [[(0, 3), (0, 4)], [(2, 0)], [(1, 2), (1, 3)]]


def test_a_single_busy_partition_keeps_the_single_partition_path():
    groups = Mock()
    worker = consumer([message(0, o) for o in range(3)], groups_handler=groups)
    assert worker.turn() == 3
    groups.assert_not_called()
    assert committed(worker) == [[(0, 3)]]


def test_batch_size_is_capped_at_the_writer_document_limit(monkeypatch):
    import sys

    class Consumer:
        def __init__(self, options):
            pass

        def subscribe(self, *args, **kwargs):
            pass

    monkeypatch.setitem(sys.modules, "confluent_kafka", SimpleNamespace(Consumer=Consumer))
    monkeypatch.setitem(
        sys.modules, "appchi.service_clients", SimpleNamespace(kafka_options=lambda _: {})
    )

    class Db:
        @contextmanager
        def transaction(self, *args, **kwargs):
            row = {"enabled": True}
            yield SimpleNamespace(execute=lambda *_: SimpleNamespace(fetchone=lambda: row))

    settings = SimpleNamespace(environment="test")
    assert MAX_BATCH == 500
    raised = ChangedConsumer(Db(), settings, None, "indexer", Mock(), batch_size=5000)
    assert raised.batch_size == 500 and raised.groups_handler is None
    assert ChangedConsumer(Db(), settings, None, "correlation", Mock()).batch_size == 50
    # Fixtures that build the consumer with __new__ inherit no shared handler.
    assert ChangedConsumer.__new__(ChangedConsumer).groups_handler is None


def test_a_lasting_fault_in_a_non_head_partition_stops_failing_shared_calls():
    shared = []

    def groups(db, settings, profile, prefixes):
        partitions = [prefix[0].partition() for prefix in prefixes]
        shared.append(partitions)
        if 2 in partitions:
            raise RuntimeError("partition 2 poisons every bulk it joins")
        return [len(prefix) for prefix in prefixes]

    def alone(db, settings, profile, value):
        group = value if isinstance(value, list) else [value]
        if group[0].partition() == 2:
            raise RuntimeError("poison")
        return len(group)

    later = [message(p, 1) for p in range(4)]
    worker = consumer(
        [message(p, 0) for p in range(4)],
        later,
        groups_handler=groups,
        batch_handler=Mock(side_effect=alone),
        handler=Mock(side_effect=alone),
    )
    # The failed shared call runs the head alone and marks the others solo.
    assert worker.turn() == 1
    assert worker.solo == {("changed", 1), ("changed", 2), ("changed", 3)}
    # Each solo partition then takes one single-partition turn; 2 is fenced.
    assert worker.turn() == 1
    assert worker.turn() == 0
    assert ("changed", 2) in worker.retries.failed
    assert worker.turn() == 1
    assert worker.solo == frozenset()
    # Later turns batch the healthy partitions again without the faulty one.
    assert worker.turn() == 3
    assert shared == [[0, 1, 2, 3], [0, 1, 3]]
    assert committed(worker)[-1] == [(0, 2), (1, 2), (3, 2)]


def test_revocation_clears_solo_marks():
    worker = consumer(groups_handler=Mock())
    worker.solo = frozenset({("changed", 1), ("changed", 2)})
    worker._revoke(worker.client, [SimpleNamespace(topic="changed", partition=1)])
    assert worker.solo == {("changed", 2)}
