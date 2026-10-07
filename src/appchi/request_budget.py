"""One monotonic HTTP budget propagated into synchronous database work."""

from contextlib import contextmanager
from contextvars import ContextVar
from time import monotonic

from appchi.shared.errors import unavailable

deadline = ContextVar("appchi_request_deadline", default=None)


def remaining(cap=None):
    end = deadline.get()
    value = None if end is None else end - monotonic()
    if value is not None and value <= 0:
        raise unavailable("request_timeout")
    return cap if value is None else value if cap is None else min(cap, value)


@contextmanager
def request_budget(seconds):
    token = deadline.set(monotonic() + seconds)
    try:
        yield
    finally:
        deadline.reset(token)
