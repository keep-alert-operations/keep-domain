"""Pytest fixtures every Keep repository uses for its log checks (REV-74).

Import both names in a ``conftest.py``::

    from keep.observability.testing import restore_logging, strict_log_events  # noqa: F401
"""

import io
import json
import logging

import pytest


@pytest.fixture(autouse=True, scope="session")
def strict_log_events():
    """An unregistered log event or field, or a missing required field, fails the test."""
    from keep.observability import logs

    logs.STRICT = True
    yield
    logs.STRICT = False


@pytest.fixture(autouse=True)
def restore_logging():
    """A test that configures logging must not change it for the tests that follow."""
    from keep.observability import http, logs

    root = logging.getLogger()
    handlers, level, detail = list(root.handlers), root.level, logs.DETAIL
    http.REPEATED_READS._state.clear()
    yield
    for handler in list(root.handlers):
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    root.setLevel(level)
    logs.DETAIL = detail


def capture_records(service, role=None):
    """Configure logging for ``service`` and return a function giving the records written."""
    from keep.observability import configure_logging

    stream = io.StringIO()
    configure_logging(service, role=role, environ={}, stream=stream)
    return lambda: [json.loads(line) for line in stream.getvalue().splitlines()]
