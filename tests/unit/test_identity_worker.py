"""The manual ADAPI refresh entry point: arguments, environment and exit codes.

Requirements: REV-73; worker scope 4 (manual ``directory --once`` only); identity
configuration 7, 12.
"""

import base64
from datetime import UTC, datetime

import pytest

from keep.identity import worker
from keep.identity.directory import FAILURE_UNAVAILABLE, DirectoryEvidence, PrincipalKey
from keep.identity.publication import PublicationResult, SaveOutcome

SECRET = "pa55-not-printed"


def outcome(root, *, saved=True, bootstrap=False, fenced=False):
    key = PrincipalKey("adapi", root)
    now = datetime.now(UTC)
    if saved:
        evidence = DirectoryEvidence("adapi", 1, now, now, frozenset({key}), {}, {}, {}, True)
    else:
        evidence = DirectoryEvidence.failed("adapi", 1, (key,), now)
    publication = PublicationResult(saved, 1, (), (), bootstrap, fenced)
    reason = None if saved else FAILURE_UNAVAILABLE
    return worker.RefreshUnit("team", (root,), SaveOutcome(evidence, publication, reason, 1))


class FakeDatabase:
    closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def environment(monkeypatch):
    for name in (
        "KEEP_SUPERADMIN_GROUP",
        "KEEP_ADAPI_URL",
        "KEEP_ADAPI_CLIENT_ID",
        "KEEP_WRAPPING_KEYRING",
        worker.BOOTSTRAP_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KEEP_DATABASE_URL", f"postgresql://keep:{SECRET}@db.invalid/keep")
    monkeypatch.setenv("KEEP_DEPLOYMENT_EPOCH", "test")
    monkeypatch.setenv("KEEP_WRAPPING_KEY", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("KEEP_ADAPI_URL", "https://adapi.invalid")
    monkeypatch.setenv("KEEP_ADAPI_CLIENT_ID", SECRET)
    monkeypatch.setenv("KEEP_SUPERADMIN_GROUP", "Keep-Admins")
    return monkeypatch


@pytest.fixture
def cycle(environment):
    calls = []
    result = [worker.RefreshSummary((outcome("keep-admins", bootstrap=True),))]

    def fake_run_cycle(database, config, superadmin, **options):
        calls.append(dict(database=database, config=config, superadmin=superadmin, **options))
        return result[0]

    environment.setattr(worker, "run_cycle", fake_run_cycle)
    return calls, result


def run(argv, capsys):
    database = FakeDatabase()
    code = worker.main(argv, connect=lambda settings: database)
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err
    return code, out.out.splitlines(), database


def test_once_is_required_because_directory_automation_is_deferred(cycle, capsys):
    with pytest.raises(SystemExit) as exit_:
        worker.main([], connect=lambda settings: FakeDatabase())
    assert exit_.value.code == 2 and cycle[0] == []
    assert "--once" in capsys.readouterr().err


def test_published_refresh_exits_zero_with_a_totals_line(cycle, capsys):
    code, lines, database = run(["--once"], capsys)
    assert code == 0 and database.closed
    assert lines == ["directory_refresh units=1 published=1 failed_roots=0 bootstrap_ready=true"]
    (call,) = cycle[0]
    assert call["database"] is database and call["superadmin"] == "keep-admins"
    assert call["config"].base_url == "https://adapi.invalid"
    assert call["config"].client_id == SECRET and SECRET not in repr(call["config"])
    assert call["bootstrap_qualified"] is False


@pytest.mark.parametrize(
    "argv,value,qualified",
    [
        (["--once", "--bootstrap"], None, True),
        (["--once"], "true", True),
        (["--once"], "TRUE", False),
        (["--once"], "1", False),
        (["--once"], "", False),
    ],
)
def test_bootstrap_is_qualified_by_the_flag_or_the_exact_environment_value(
    cycle, environment, capsys, argv, value, qualified
):
    if value is not None:
        environment.setenv(worker.BOOTSTRAP_ENV, value)
    assert run(argv, capsys)[0] == 0
    assert cycle[0][-1]["bootstrap_qualified"] is qualified


def test_failed_roots_are_listed_and_exit_one(cycle, capsys):
    calls, result = cycle
    result[0] = worker.RefreshSummary(
        (
            outcome("keep-admins"),
            outcome("team05", saved=False),
            outcome("team07", saved=False, fenced=True),
        )
    )
    code, lines, database = run(["--once"], capsys)
    assert code == 1 and database.closed
    assert lines == [
        "directory_root_failed root=team05 reason=directory_unavailable",
        "directory_root_failed root=team07 reason=directory_publication_incomplete",
        "directory_refresh units=3 published=1 failed_roots=2 bootstrap_ready=false",
    ]


@pytest.mark.parametrize(
    "variable,reason",
    [
        ("KEEP_SUPERADMIN_GROUP", worker.SUPERADMIN_REQUIRED),
        ("KEEP_ADAPI_URL", worker.ADAPI_REQUIRED),
        ("KEEP_ADAPI_CLIENT_ID", worker.ADAPI_REQUIRED),
    ],
)
def test_missing_configuration_fails_before_any_refresh(cycle, capsys, variable, reason):
    with pytest.MonkeyPatch.context() as patch:
        patch.delenv(variable)
        code, lines, database = run(["--once"], capsys)
    assert code == 1 and database.closed and cycle[0] == []
    assert lines == [f"directory_refresh_failed reason={reason}"]


def test_invalid_settings_print_a_reason_and_never_the_values(cycle, capsys):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("KEEP_ADAPI_URL", f"https://user:{SECRET}@adapi.invalid")
        code, lines, _ = run(["--once"], capsys)
    assert code == 1 and cycle[0] == []
    assert lines == [f"directory_refresh_failed reason={worker.CONFIGURATION_INVALID}"]


def test_unexpected_errors_print_the_type_only(cycle, capsys, environment):
    def broken(*args, **kwargs):
        raise RuntimeError(f"connection to postgresql://keep:{SECRET}@db failed")

    environment.setattr(worker, "run_cycle", broken)
    code, lines, database = run(["--once"], capsys)
    assert code == 1 and database.closed
    assert lines == ["directory_refresh_failed reason=internal_error type=RuntimeError"]


def test_refresh_emits_the_same_lines_for_both_entry_points(cycle):
    from keep.config import Settings

    lines = []
    summary = worker.refresh(
        FakeDatabase(), Settings(role="directory"), bootstrap_qualified=True, emit=lines.append
    )
    assert summary.ok and lines == worker.summary_lines(summary)
    assert cycle[0][-1]["bootstrap_qualified"] is True


def test_bootstrap_from_environment_reads_only_true():
    assert worker.bootstrap_from_environment({worker.BOOTSTRAP_ENV: "true"})
    assert not worker.bootstrap_from_environment({worker.BOOTSTRAP_ENV: "yes"})
    assert not worker.bootstrap_from_environment({})
