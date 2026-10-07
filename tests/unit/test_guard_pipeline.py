"""Guard commands remain ordered statements and uncertain session locks close."""

from contextlib import contextmanager

import pytest

from appchi.recovery.guard import runtime_guard
from appchi.shared.errors import AppError


class Connection:
    def __init__(self, *, fail_flush=None, acquired=True, fenced=False):
        self.fail_flush, self.acquired, self.fenced = fail_flush, acquired, fenced
        self.closed = False
        self.in_pipeline = False
        self.statements, self.batches = [], []

    @contextmanager
    def transaction(self):
        yield

    @contextmanager
    def pipeline(self):
        start = len(self.statements)
        self.in_pipeline = True
        try:
            yield
        finally:
            self.in_pipeline = False
            self.batches.append(self.statements[start:])
            if len(self.batches) == self.fail_flush:
                raise RuntimeError("controlled unknown pipeline result")

    def execute(self, query, params=None):
        assert self.in_pipeline
        self.statements.append(query)
        connection = self

        class Cursor:
            def fetchone(self):
                assert not connection.in_pipeline
                if "pg_try_advisory" in query:
                    return {"acquired": connection.acquired}
                if "pg_advisory_unlock" in query:
                    return {"released": True}
                return {"deployment_epoch": "epoch", "fenced": connection.fenced}

        return Cursor()

    def close(self):
        self.closed = True


def test_guard_batches_roundtrips_but_keeps_acquisition_and_control_separate():
    connection = Connection()
    with runtime_guard(connection, "epoch"):
        assert not connection.in_pipeline
        assert len(connection.batches) == 1
        assert "pg_try_advisory" in connection.batches[0][-2]
        assert connection.batches[0][-1].startswith("SELECT deployment_epoch")
    assert len(connection.batches) == 2
    assert "pg_advisory_unlock" in connection.batches[1][-1]
    assert not connection.closed


@pytest.mark.parametrize("phase", [1, 2])
def test_unknown_acquisition_or_release_closes_connection(phase):
    connection = Connection(fail_flush=phase)
    entered = False
    with pytest.raises(RuntimeError, match="unknown pipeline result"):
        with runtime_guard(connection, "epoch"):
            entered = True
    assert entered == (phase == 2)
    assert connection.closed


@pytest.mark.parametrize(
    "acquired,fenced,code",
    [
        (False, False, "restore_in_progress"),
        (True, True, "restore_reconciliation_required"),
    ],
)
def test_guard_still_rejects_locked_or_fenced_authority(acquired, fenced, code):
    connection = Connection(acquired=acquired, fenced=fenced)
    with pytest.raises(AppError, match=code):
        with runtime_guard(connection, "epoch"):
            pytest.fail("Fenced business transaction entered")
    assert len(connection.batches) == (2 if acquired else 1)
