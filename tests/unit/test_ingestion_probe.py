import builtins

import pytest

from keep import probes


@pytest.mark.parametrize("role", ["ingestion-api", "private-ingestion"])
def test_ingestion_cli_probe_does_not_import_sql(role, monkeypatch):
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "keep.db" or name.startswith("psycopg"):
            pytest.fail("Ingestion readiness imported the SQL adapter")
        return original(name, *args, **kwargs)

    observed = []
    monkeypatch.setattr("builtins.__import__", guarded)
    monkeypatch.setattr("keep.config.Settings", lambda **kw: kw)
    monkeypatch.setattr(probes, "check_readiness", lambda settings, db: observed.append((settings, db)))
    monkeypatch.setattr("sys.argv", ["probes", role])
    probes.main()
    assert observed == [({"role": role}, None)]
