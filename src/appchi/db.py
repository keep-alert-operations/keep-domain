from contextlib import contextmanager, nullcontext

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


class Database:
    def __init__(self, url: str, size: int = 4, *, deployment_epoch: str | None = None):
        self.deployment_epoch = deployment_epoch
        self.pool = ConnectionPool(
            url, min_size=0, max_size=size, timeout=3, kwargs={"row_factory": dict_row}, open=True
        )

    @contextmanager
    def transaction(self, tenant_id=None):
        from appchi.recovery.guard import runtime_guard
        from appchi.alert_notifications import pending, publish_best_effort

        batch = []
        token = pending.set(batch)
        try:
            with self.pool.connection() as conn:
                with self._transaction(conn, tenant_id, runtime_guard):
                    yield conn
        except BaseException:
            raise
        else:
            publish_best_effort(batch)
        finally:
            pending.reset(token)

    @contextmanager
    def _transaction(self, conn, tenant_id, runtime_guard):
        guard = (
            runtime_guard(conn, self.deployment_epoch)
            if self.deployment_epoch is not None
            else nullcontext()
        )
        with guard, conn.transaction():
            conn.execute("SET LOCAL TIME ZONE 'UTC'")
            conn.execute("SET LOCAL statement_timeout = '4000ms'")
            conn.execute("SET LOCAL lock_timeout = '2000ms'")
            if tenant_id:
                conn.execute("SELECT set_config('appchi.tenant_id', %s, true)", (str(tenant_id),))
            yield conn
            from appchi.maintenance.runtime import flush_inline_effects

            flush_inline_effects(conn)

    def close(self):
        self.pool.close()
