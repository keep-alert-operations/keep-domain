"""Compiler availability diagnostics never include source or child error text."""

import logging

import pytest

from appchi.cel import compiler
from appchi.correlation import repository
from appchi.shared.errors import AppError


@pytest.mark.parametrize("reason", ["deadline", "worker_crashed", "child_unavailable"])
def test_unavailable_logging_is_sanitized_and_preserves_public_error(monkeypatch, caplog, reason):
    private_source = 'message == "synthetic-private-source"'
    private_error = "synthetic-private-native-detail\nforged-log-event"

    class Pipe:
        def close(self):
            pass

        def poll(self, timeout):
            assert timeout == compiler.COMPILE_TIMEOUT_SECONDS == 1
            return reason != "deadline"

        def recv(self):
            if reason == "worker_crashed":
                raise EOFError()
            return ("unavailable", private_error)

    class Process:
        exitcode = None if reason == "deadline" else 1

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return False

    class Context:
        def Pipe(self, duplex):
            assert duplex is False
            return Pipe(), Pipe()

        def Process(self, **kwargs):
            return Process()

    monkeypatch.setattr(compiler.multiprocessing, "get_context", lambda method: Context())
    monkeypatch.setattr(compiler, "_checked_cache", compiler._CompileCache())
    with caplog.at_level(logging.WARNING, logger=compiler.__name__):
        with pytest.raises(AppError) as error:
            repository.compile_conditions(
                {"conditions": [{"id": "fixture", "cel": private_source}]}
            )
    assert error.value.code == "cel_compilation_unavailable"
    assert error.value.status == 503
    records = [record for record in caplog.records if record.name == compiler.__name__]
    assert len(records) == 1
    text = records[0].getMessage()
    assert f"reason={reason}" in text
    assert "elapsed_ms=" in text and "rule=True" in text and "child_exit_code=" in text
    assert private_source not in caplog.text
    assert "synthetic-private" not in caplog.text
    assert "forged-log-event" not in caplog.text
    assert records[0].exc_info is None
