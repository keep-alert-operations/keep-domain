"""Hot unscoped units take the restore guard inside their single transaction."""

from types import SimpleNamespace
from unittest.mock import Mock

from keep.kafka_changed import ChangedConsumer
from test_restore_guard_transaction import (
    CONTROL,
    SESSION_LOCK,
    XACT_LOCK,
    Connection,
    Server,
    database,
    position,
)


def message(partition, offset):
    return SimpleNamespace(
        topic=lambda: "changed", partition=lambda: partition, offset=lambda: offset
    )


def test_changed_positions_flush_is_one_transaction_with_the_guard_inside():
    server = Server()
    connection = Connection(server)
    worker = ChangedConsumer.__new__(ChangedConsumer)
    worker.db, worker.role, worker.client = database(connection), "correlation", Mock()
    worker.uncommitted = {("changed", 0): message(0, 4), ("changed", 1): message(1, 9)}
    worker.uncommitted_count, worker.uncommitted_since = 2, 0.0

    worker.flush()

    # No preliminary guard or lock-release transaction around the positions write.
    [unit] = connection.transactions
    assert unit["outcome"] == "commit"
    statements = unit["statements"]
    assert (
        position(statements, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        < position(statements, XACT_LOCK)
        < position(statements, CONTROL)
        < position(statements, "kafka_consumer_positions")
    )
    assert not any(SESSION_LOCK in query or "unlock" in query for query in statements)
    assert server.try_restore() and not connection.closed
