"""Physical-index writer fences shared by projection and rebuild workers."""

from contextlib import contextmanager
from uuid import uuid4

from appchi.shared.errors import unavailable


def control(conn):
    return conn.execute("SELECT * FROM search_index_control WHERE singleton FOR SHARE").fetchone()


def check_writer(conn, physical_index, epoch):
    current = control(conn)
    if current and (
        current["writers_paused"]
        or current["physical_index"] != physical_index
        or current["index_epoch"] != epoch
    ):
        raise unavailable("projection_fenced")


@contextmanager
def writer_lease(db, settings):
    identity = uuid4()
    with db.transaction() as conn:
        current = control(conn)
        if not current:
            if settings.environment != "development":
                raise unavailable("search_binding_required")
            yield_index = settings.elasticsearch_index
            epoch = None
        else:
            if current["writers_paused"] or current["alias_name"] != settings.elasticsearch_index:
                raise unavailable("projection_fenced")
            yield_index, epoch = current["physical_index"], current["index_epoch"]
        # A configured binding always writes the captured physical index, never
        # a mutable alias. Expired external work can only touch the old index.
        conn.execute(
            "INSERT INTO search_writer_leases(id,index_epoch,expires_at) VALUES(%s,%s,clock_timestamp()+interval '20 seconds')",
            (identity, epoch or "development"),
        )
    try:
        yield yield_index
    finally:
        with db.transaction() as conn:
            conn.execute("DELETE FROM search_writer_leases WHERE id=%s", (identity,))


def check_search(conn):
    """Rebuild pause is independent of qualification and restore readiness."""
    paused = conn.execute(
        "SELECT writers_paused FROM search_index_control WHERE singleton"
    ).fetchone()
    if paused and paused["writers_paused"]:
        raise unavailable("search_rebuild_cutover")
