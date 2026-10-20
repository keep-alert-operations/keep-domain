"""READ COMMITTED units take the restore guard inside their own transaction."""

from contextlib import contextmanager
from uuid import uuid4

import pytest

from appchi.db import BudgetConnection, Database
from appchi.request_budget import request_budget
from appchi.shared.errors import AppError

TENANT = uuid4()
XACT_LOCK = "pg_try_advisory_xact_lock_shared"
SESSION_LOCK = "pg_try_advisory_lock_shared"
CONTROL = "SELECT deployment_epoch,fenced FROM restore_control"
ISOLATION = "SET TRANSACTION ISOLATION LEVEL"


class ActiveSqlTransaction(Exception):
    """PostgreSQL's refusal to change isolation after the first query."""


class Server:
    """Shared advisory-lock and restore_control state seen by every session."""

    def __init__(self, control="current"):
        current = {"deployment_epoch": "epoch", "fenced": False}
        self.control = current if control == "current" else control
        self.restoring = False
        self.holders = set()

    def try_restore(self):
        # Restore's exclusive pg_advisory_xact_lock conflicts with any shared holder.
        return not self.holders


class Connection:
    def __init__(self, server, *, fail_flush=None):
        self.server, self.fail_flush = server, fail_flush
        self.closed = self.in_pipeline = False
        self.transactions, self.batches = [], []
        self.depth = 0
        self.snapshot, self.isolation = False, "read committed"

    def holds(self, level):
        return (self, level) in self.server.holders

    @contextmanager
    def transaction(self, *args, **kwargs):
        assert not self.in_pipeline and self.depth == 0
        record = {"statements": [], "outcome": None}
        self.transactions.append(record)
        self.depth, self.snapshot, self.isolation = 1, False, "read committed"
        try:
            yield
        except BaseException:
            record["outcome"] = "rollback"
            raise
        else:
            record["outcome"] = "commit"
        finally:
            self.depth = 0
            self.server.holders.discard((self, "xact"))

    @contextmanager
    def pipeline(self):
        start = len(self.transactions[-1]["statements"])
        self.in_pipeline = True
        try:
            yield
        finally:
            self.in_pipeline = False
            self.batches.append(self.transactions[-1]["statements"][start:])
            if len(self.batches) == self.fail_flush:
                raise RuntimeError("controlled unknown pipeline result")

    def execute(self, query, params=None):
        assert self.depth == 1, "every statement runs inside a transaction"
        self.transactions[-1]["statements"].append(query)
        if query.startswith(ISOLATION):
            level = "repeatable read" if "REPEATABLE READ" in query else "read committed"
            if self.snapshot and level != self.isolation:
                raise ActiveSqlTransaction("isolation must be set before any query")
            self.isolation = level
        if query.startswith("SELECT"):
            self.snapshot = True
        row = None
        if XACT_LOCK in query or SESSION_LOCK in query:
            acquired = not self.server.restoring
            if acquired:
                self.server.holders.add((self, "xact" if XACT_LOCK in query else "session"))
            row = {"acquired": acquired}
        elif "pg_advisory_unlock_shared" in query:
            row = {"released": self.holds("session")}
            self.server.holders.discard((self, "session"))
        elif query.startswith(CONTROL):
            row = None if self.server.control is None else dict(self.server.control)
        connection = self

        class Cursor:
            def fetchone(self):
                assert not connection.in_pipeline, "results are read after the pipeline syncs"
                return row

        return Cursor()

    def close(self):
        self.closed = True


class Pool:
    def __init__(self, connection):
        self.held = connection

    @contextmanager
    def connection(self, timeout=None):
        yield self.held


def database(connection, epoch="epoch"):
    db = Database.__new__(Database)
    db.deployment_epoch, db.pool = epoch, Pool(connection)
    return db


def statements(connection):
    return [query for record in connection.transactions for query in record["statements"]]


def position(batch, fragment):
    return next(index for index, query in enumerate(batch) if fragment in query)


PATHS = {
    "tenant": {"tenant_id": TENANT},
    "read_committed": {"read_committed": True},
    "session": {},
}


@pytest.mark.parametrize("path", ["tenant", "read_committed"])
def test_eligible_unit_guards_inside_its_single_transaction(path):
    server = Server()
    connection = Connection(server)
    with database(connection).transaction(**PATHS[path]) as conn:
        assert conn is connection
        assert connection.holds("xact") and not connection.holds("session")
        assert not server.try_restore(), "restore must drain behind the shared lock"
        conn.execute("UPDATE alerts SET revision=revision+1")
    assert [record["outcome"] for record in connection.transactions] == ["commit"]
    setup = connection.batches[0]
    assert len(connection.batches) == 1
    isolation, acquisition, control = (
        position(setup, ISOLATION),
        position(setup, XACT_LOCK),
        position(setup, CONTROL),
    )
    # Pinned READ COMMITTED precedes every SELECT; the control read is a later
    # statement, so it takes its snapshot after the lock is granted.
    assert isolation < acquisition < control
    assert setup[isolation] == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
    assert not any(query.startswith("SELECT") for query in setup[:isolation])
    if path == "tenant":
        assert control < position(setup, "set_config('appchi.tenant_id'")
    else:
        assert not any("set_config" in query for query in setup)
    assert not any(
        "pg_advisory_unlock" in query or SESSION_LOCK in query for query in statements(connection)
    )
    assert server.try_restore() and not connection.closed


def test_unscoped_default_keeps_session_guard_for_repeatable_read():
    server = Server()
    connection = Connection(server)
    with database(connection).transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        assert connection.isolation == "repeatable read"
        assert connection.holds("session") and not connection.holds("xact")
        assert not server.try_restore()
        conn.execute("SELECT 1")
    guard, business, release = connection.transactions
    assert [guard["outcome"], business["outcome"], release["outcome"]] == ["commit"] * 3
    assert any(SESSION_LOCK in query for query in guard["statements"])
    assert any("pg_advisory_unlock_shared" in query for query in release["statements"])
    business_setup = connection.batches[1]
    assert business_setup and all(query.startswith("SET LOCAL") for query in business_setup)
    assert not any(XACT_LOCK in query or ISOLATION in query for query in business_setup)
    assert server.try_restore() and not connection.closed


@pytest.mark.parametrize("path", ["tenant", "read_committed"])
def test_in_transaction_guard_refuses_a_later_repeatable_read_switch(path):
    server = Server()
    connection = Connection(server)
    with pytest.raises(ActiveSqlTransaction):
        with database(connection).transaction(**PATHS[path]) as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            pytest.fail("A stale control snapshot must never reach business work")
    assert [record["outcome"] for record in connection.transactions] == ["rollback"]
    assert server.try_restore()


@pytest.mark.parametrize("path", sorted(PATHS))
@pytest.mark.parametrize(
    "restoring,control,code",
    [
        (True, {"deployment_epoch": "epoch", "fenced": False}, "restore_in_progress"),
        (False, {"deployment_epoch": "epoch", "fenced": True}, "restore_reconciliation_required"),
        (False, None, "restore_reconciliation_required"),
        (False, {"deployment_epoch": "previous", "fenced": False}, "deployment_epoch_fenced"),
    ],
)
def test_both_guards_fail_fast_with_the_same_codes(path, restoring, control, code):
    server = Server(control)
    server.restoring = restoring
    connection = Connection(server)
    with pytest.raises(AppError) as error:
        with database(connection).transaction(**PATHS[path]):
            pytest.fail("A fenced business transaction entered")
    assert error.value.code == code and error.value.status == 503
    assert not server.holders and not connection.closed
    outcomes = [record["outcome"] for record in connection.transactions]
    if path == "session":
        # The business transaction never began; an acquired lock is released.
        assert outcomes == (["rollback"] if restoring else ["rollback", "commit"])
    else:
        assert outcomes == ["rollback"]


@pytest.mark.parametrize("path", sorted(PATHS))
@pytest.mark.parametrize("epoch", [None, "epoch"])
def test_current_or_unset_control_epoch_admits_the_unit(path, epoch):
    server = Server({"deployment_epoch": epoch, "fenced": False})
    connection = Connection(server)
    with database(connection).transaction(**PATHS[path]):
        pass
    assert connection.transactions[-1]["outcome"] == "commit"
    assert not server.holders


@pytest.mark.parametrize("path", ["tenant", "read_committed"])
def test_business_failure_rolls_back_and_releases_the_transaction_lock(path):
    server = Server()
    connection = Connection(server)
    with pytest.raises(RuntimeError, match="controlled rollback"):
        with database(connection).transaction(**PATHS[path]):
            assert connection.holds("xact")
            raise RuntimeError("controlled rollback")
    assert [record["outcome"] for record in connection.transactions] == ["rollback"]
    assert server.try_restore() and not connection.closed
    assert not any("pg_advisory_unlock" in query for query in statements(connection))


@pytest.mark.parametrize("path", ["tenant", "read_committed"])
def test_uncertain_setup_pipeline_leaves_no_lock_to_leak(path):
    server = Server()
    connection = Connection(server, fail_flush=1)
    with pytest.raises(RuntimeError, match="unknown pipeline result"):
        with database(connection).transaction(**PATHS[path]):
            pytest.fail("Unproven guard must not enter business work")
    # Only a transaction-level lock was requested; rollback or disconnect drops
    # it, so the connection need not be discarded for lock safety.
    assert [record["outcome"] for record in connection.transactions] == ["rollback"]
    assert not server.holders


@pytest.mark.parametrize("path", sorted(PATHS))
def test_epochless_administrative_database_runs_no_guard(path):
    server = Server()
    connection = Connection(server)
    with database(connection, epoch=None).transaction(**PATHS[path]):
        pass
    executed = statements(connection)
    assert len(connection.transactions) == 1
    assert not any(
        "advisory" in query or ISOLATION in query or CONTROL in query for query in executed
    )


def test_budgeted_tenant_unit_keeps_its_short_statement_deadline():
    server = Server()
    connection = Connection(server)
    with request_budget(0.5), database(connection).transaction(TENANT) as conn:
        assert isinstance(conn, BudgetConnection)
        assert connection.holds("xact")
    setup = connection.batches[0]
    deadlines = [
        int(query.split("'")[1].removesuffix("ms"))
        for query in setup
        if query.startswith("SET LOCAL statement_timeout")
    ]
    assert deadlines and all(0 < value <= 500 for value in deadlines)
    assert position(setup, "statement_timeout") < position(setup, XACT_LOCK)
    assert len(connection.transactions) == 1
    assert server.try_restore()
