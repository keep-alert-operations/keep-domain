"""Fields bound to the work in progress, carried on every record it writes."""

from contextlib import contextmanager
from contextvars import ContextVar

# Never mutated: every change installs a new mapping, so copied contexts stay isolated.
_bound: ContextVar[dict] = ContextVar("keep_log_context", default={})


def current():
    return _bound.get()


@contextmanager
def bind(**fields):
    """Bind fields for the enclosed work, for example one HTTP request."""
    token = _bound.set(
        {**_bound.get(), **{k: v for k, v in fields.items() if v is not None}}
    )
    try:
        yield
    finally:
        _bound.reset(token)


def bind_more(**fields):
    """Add fields learned part-way through, until the enclosing bind ends.

    A handler running in a worker thread or child task has a copy of the context,
    so this reaches the records that handler writes, not its caller's.
    """
    _bound.set({**_bound.get(), **{k: v for k, v in fields.items() if v is not None}})
