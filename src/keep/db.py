from contextlib import contextmanager, nullcontext

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from keep.request_budget import deadline, remaining


class BudgetConnection:
    """Retain psycopg behavior while bounding each statement by remaining time."""

    def __init__(self, connection):
        self.connection = connection
        self.statement_ms = None

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def bound_statement(self):
        milliseconds = max(1, int(remaining(4) * 1000))
        if self.statement_ms is None or milliseconds < self.statement_ms:
            self.connection.execute(f"SET LOCAL statement_timeout = '{milliseconds}ms'")
            self.statement_ms = milliseconds

    def statement_completed(self, query):
        # Runtime recovery guards explicitly change this setting. SET LOCAL also
        # expires at transaction/savepoint boundaries, so cached values must not
        # survive either path. Application queries are trusted SQL, not input.
        statement = str(query).lower()
        if (
            "statement_timeout" in statement
            or "reset all" in statement
            or "discard all" in statement
        ):
            self.statement_ms = None
        remaining()

    def execute(self, *args, **kwargs):
        self.bound_statement()
        result = self.connection.execute(*args, **kwargs)
        self.statement_completed(args[0] if args else kwargs["query"])
        return BudgetCursor(result, self)

    def cursor(self, *args, **kwargs):
        remaining()
        return BudgetCursor(self.connection.cursor(*args, **kwargs), self)

    @contextmanager
    def transaction(self, *args, **kwargs):
        self.statement_ms = None
        try:
            with self.connection.transaction(*args, **kwargs) as transaction:
                yield transaction
        finally:
            self.statement_ms = None


class BudgetCursor:
    """Apply the same deadline to cursor writes and incremental result reads."""

    def __init__(self, cursor, connection):
        self.cursor = cursor
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.cursor, name)

    def __enter__(self):
        self.cursor.__enter__()
        return self

    def __exit__(self, *args):
        return self.cursor.__exit__(*args)

    def execute(self, *args, **kwargs):
        self.connection.bound_statement()
        self.cursor.execute(*args, **kwargs)
        self.connection.statement_completed(args[0] if args else kwargs["query"])
        return self

    def executemany(self, query, params_seq, *, returning=False):
        if returning:
            # No application caller uses multiple RETURNING result sets. Do not
            # silently weaken the deadline by queuing an unbounded pipeline.
            raise ValueError("Budgeted executemany does not support returning=True")
        for params in params_seq:
            self.execute(query, params)

    def _fetch(self, method, *args):
        remaining()
        if getattr(self.cursor, "name", None):
            self.connection.bound_statement()
        result = getattr(self.cursor, method)(*args)
        remaining()
        return result

    def fetchone(self):
        return self._fetch("fetchone")

    def fetchmany(self, size=0):
        return self._fetch("fetchmany", size)

    def fetchall(self):
        return self._fetch("fetchall")

    def nextset(self):
        return self._fetch("nextset")

    def __iter__(self):
        return self

    def __next__(self):
        remaining()
        if getattr(self.cursor, "name", None):
            self.connection.bound_statement()
        result = next(self.cursor)
        remaining()
        return result


class Database:
    def __init__(self, url: str, size: int = 4, *, deployment_epoch: str | None = None):
        self.deployment_epoch = deployment_epoch
        self.pool = ConnectionPool(
            url, min_size=0, max_size=size, timeout=3, kwargs={"row_factory": dict_row}, open=True
        )

    @contextmanager
    def transaction(self, tenant_id=None, *, read_committed=False):
        """Run one restore-guarded unit of work.

        Tenant-scoped units, and unscoped callers passing read_committed=True,
        stay READ COMMITTED and take the restore guard inside the transaction.
        Other unscoped callers may select REPEATABLE READ before their first
        query, so the session-lock guard still runs around their transaction.
        """
        from keep.recovery.guard import runtime_guard
        from keep.alert_notifications import pending, publish_best_effort
        from keep.observability import flow as alert_flow

        batch = []
        token = pending.set(batch)
        # Log steps noted inside this unit of work are true only once it commits
        # (observability 3): written after the commit, dropped on rollback.
        flow = alert_flow.active()
        mark = flow.mark() if flow is not None else 0
        try:
            with self.pool.connection(timeout=remaining(3)) as conn:
                conn = BudgetConnection(conn) if deadline.get() is not None else conn
                with self._transaction(
                    conn, tenant_id, runtime_guard, read_committed=read_committed
                ):
                    yield conn
        except BaseException:
            if flow is not None:
                flow.discard(mark)
            raise
        else:
            if flow is not None:
                flow.settle(mark)
            publish_best_effort(batch)
        finally:
            pending.reset(token)

    @contextmanager
    def _transaction(self, conn, tenant_id, runtime_guard, *, read_committed=False):
        from keep.recovery.guard import queue_transaction_guard, require_transaction_guard

        guarded = self.deployment_epoch is not None
        # The tenant set_config SELECT already rules out a later isolation change.
        in_transaction = guarded and (bool(tenant_id) or read_committed)
        guard = (
            runtime_guard(conn, self.deployment_epoch)
            if guarded and not in_transaction
            else nullcontext()
        )
        queued = None
        with guard, conn.transaction():
            # Only setup is pipelined. Keep SET commands (not SELECTs) for
            # unscoped callers which may select REPEATABLE READ before queries.
            with conn.pipeline():
                conn.execute("SET LOCAL TIME ZONE 'UTC'")
                if not isinstance(conn, BudgetConnection):
                    conn.execute("SET LOCAL statement_timeout = '4000ms'")
                conn.execute("SET LOCAL lock_timeout = '2000ms'")
                if in_transaction:
                    queued = queue_transaction_guard(conn)
                if tenant_id:
                    conn.execute(
                        "SELECT set_config('keep.tenant_id', %s, true)", (str(tenant_id),)
                    )
            if queued is not None:
                require_transaction_guard(queued, self.deployment_epoch)
            yield conn
            from keep.maintenance.runtime import flush_inline_effects

            flush_inline_effects(conn)
            # An expired handler must not start another unit or commit a local
            # command after its budget; the transaction rolls back on expiry.
            remaining()

    def close(self):
        self.pool.close()
