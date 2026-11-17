"""The ADAPI refresh entry point: arguments, environment, exit codes, logs and stopping.

Requirements: REV-73; REV-75; worker scope 4 (``directory --once`` only, run daily by
the CronJob or by hand); identity configuration 7, 9, 12, 13; observability 2, 4.
"""

import base64
import json
import re
import signal
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import parse_qs

import httpx
import pytest

from keep.identity import worker
from keep.identity.directory import FAILURE_UNAVAILABLE, DirectoryEvidence, PrincipalKey
from keep.identity.publication import PublicationResult, SaveOutcome

SECRET = "pa55-not-printed"
DSN_HOST = "db-host.invalid"
ADAPI_HOST = "adapi-host.invalid"


def outcome(root, *, saved=True, bootstrap=False, fenced=False, kind="team", roots=None):
    keys = [PrincipalKey("adapi", name) for name in (roots or (root,))]
    now = datetime.now(UTC)
    if saved:
        evidence = DirectoryEvidence("adapi", 1, now, now, frozenset(keys), {}, {}, {}, True)
    else:
        evidence = DirectoryEvidence.failed("adapi", 1, keys, now)
    publication = PublicationResult(saved, 1, (), bootstrap, fenced)
    reason = None if saved else FAILURE_UNAVAILABLE
    return worker.RefreshUnit(
        kind, tuple(roots or (root,)), SaveOutcome(evidence, publication, reason, 1)
    )


class FakeDatabase:
    closed = False

    def close(self):
        self.closed = True

    @contextmanager
    def transaction(self):
        yield None


@pytest.fixture
def environment(monkeypatch):
    for name in (
        "KEEP_SUPERADMIN_GROUP",
        "KEEP_ADAPI_URL",
        "KEEP_ADAPI_CLIENT_ID",
        "KEEP_WRAPPING_KEYRING",
        "KEEP_LOG_SHIP_URL",
        "KEEP_LOG_FORMAT",
        "KEEP_LOG_LEVEL",
        worker.BOOTSTRAP_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KEEP_DATABASE_URL", f"postgresql://keep:{SECRET}@{DSN_HOST}/keep")
    monkeypatch.setenv("KEEP_DEPLOYMENT_EPOCH", "test")
    monkeypatch.setenv("KEEP_WRAPPING_KEY", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("KEEP_ADAPI_URL", f"https://{ADAPI_HOST}")
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


def records_of(err):
    return [json.loads(line) for line in err.splitlines() if line.startswith("{")]


def run(argv, capsys, *, transport=None):
    database = FakeDatabase()
    code = worker.main(argv, connect=lambda settings: database, transport=transport)
    out = capsys.readouterr()
    # A8: the ClientId, the DSN and the ADAPI address never reach stdout or a record.
    for secret in (SECRET, DSN_HOST, ADAPI_HOST):
        assert secret not in out.out + out.err
    return code, out.out.splitlines(), database, records_of(out.err)


def events(records, action):
    return [record for record in records if record["event"]["action"] == action]


def test_once_is_required_because_directory_automation_is_deferred(cycle, capsys):
    with pytest.raises(SystemExit) as exit_:
        worker.main([], connect=lambda settings: FakeDatabase())
    assert exit_.value.code == 2 and cycle[0] == []
    assert "--once" in capsys.readouterr().err


@pytest.mark.parametrize("budget", ["0", "-5", "soon", "inf", "nan"])
def test_the_budget_must_be_a_positive_number_of_seconds(cycle, capsys, budget):
    """Requirements: REV-75 (run budget)."""
    with pytest.raises(SystemExit) as exit_:
        worker.main(["--once", "--budget-seconds", budget], connect=lambda s: FakeDatabase())
    assert exit_.value.code == 2 and cycle[0] == []


def test_published_refresh_exits_zero_with_a_totals_line(cycle, capsys):
    code, lines, database, _ = run(["--once"], capsys)
    assert code == 0 and database.closed
    assert lines == ["directory_refresh units=1 published=1 failed_roots=0 bootstrap_ready=true"]
    (call,) = cycle[0]
    assert call["database"] is database and call["superadmin"] == "keep-admins"
    assert call["config"].base_url == f"https://{ADAPI_HOST}"
    assert call["config"].client_id == SECRET and SECRET not in repr(call["config"])
    assert call["bootstrap_qualified"] is False
    assert call["stop"] is not None and not call["stop"].is_set()


def test_a_published_refresh_logs_one_completed_record_as_the_refresh_role(cycle, capsys):
    """Requirements: REV-75 (logs); observability 2, 5."""
    code, _, _, records = run(["--once"], capsys)
    assert code == 0
    (completed,) = events(records, "directory_refresh_completed")
    assert completed["service"]["name"] == "api"
    assert completed["keep"]["role"] == "directory-refresh"
    assert completed["log"]["level"] == "info" and completed["event"]["outcome"] == "success"
    assert completed["log"]["logger"] == "keep.identity.worker"
    assert completed["keep"]["units"] == 1 and completed["keep"]["published"] == 1
    assert completed["keep"]["failed_roots"] == 0
    assert isinstance(completed["event"]["duration"], int)
    assert not events(records, "directory_root_failed")
    assert not events(records, "directory_refresh_failed")


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
    code, lines, database, _ = run(["--once"], capsys)
    assert code == 1 and database.closed
    assert lines == [
        "directory_root_failed root=team05 reason=directory_unavailable",
        "directory_root_failed root=team07 reason=directory_publication_incomplete",
        "directory_refresh units=3 published=1 failed_roots=2 bootstrap_ready=false",
    ]


def test_failed_units_are_logged_without_any_persons_name(cycle, capsys):
    """Requirements: REV-75 (logs); observability 4 (no user names), 5 (one record per fact)."""
    calls, result = cycle
    result[0] = worker.RefreshSummary(
        (
            outcome(None, saved=False, kind="user", roots=("alice.secret", "bob.secret")),
            outcome("keep-admins"),
            outcome("team07", saved=False, fenced=True),
        )
    )
    code, lines, _, records = run(["--once"], capsys)
    assert code == 1
    # stdout is unchanged: it still names every failed root.
    assert "directory_root_failed root=alice.secret reason=directory_unavailable" in lines
    failed = events(records, "directory_root_failed")
    assert [(r["keep"]["kind"], r["keep"].get("root"), r["keep"].get("count")) for r in failed] == [
        ("user", None, 2),
        ("team", "team07", None),
    ]
    assert [r["keep"]["reason"] for r in failed] == [
        "directory_unavailable",
        "directory_publication_incomplete",
    ]
    assert all(r["log"]["level"] == "warning" for r in failed)
    (completed,) = events(records, "directory_refresh_completed")
    assert completed["log"]["level"] == "warning" and completed["event"]["outcome"] == "failure"
    assert (completed["keep"]["units"], completed["keep"]["published"]) == (3, 1)
    assert completed["keep"]["failed_roots"] == 3
    assert "secret" not in json.dumps(records)


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
        code, lines, database, records = run(["--once"], capsys)
    assert code == 1 and database.closed and cycle[0] == []
    assert lines == [f"directory_refresh_failed reason={reason}"]
    (failed,) = events(records, "directory_refresh_failed")
    assert failed["keep"]["reason"] == reason and failed["log"]["level"] == "error"
    assert not events(records, "directory_refresh_completed")


def test_invalid_settings_print_a_reason_and_never_the_values(cycle, capsys):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("KEEP_ADAPI_URL", f"https://user:{SECRET}@{ADAPI_HOST}")
        code, lines, _, records = run(["--once"], capsys)
    assert code == 1 and cycle[0] == []
    assert lines == [f"directory_refresh_failed reason={worker.CONFIGURATION_INVALID}"]
    (failed,) = events(records, "directory_refresh_failed")
    assert failed["keep"]["reason"] == worker.CONFIGURATION_INVALID


def test_unexpected_errors_print_the_type_only(cycle, capsys, environment):
    """Requirements: REV-75 (logs); observability 4. Plan A8."""

    def broken(*args, **kwargs):
        raise RuntimeError(
            f"connection to postgresql://keep:{SECRET}@{DSN_HOST}/keep failed while reading "
            f"https://{ADAPI_HOST}/users/user?samAccountName=alice (ClientId {SECRET})"
        )

    environment.setattr(worker, "run_cycle", broken)
    code, lines, database, records = run(["--once"], capsys)
    assert code == 1 and database.closed
    assert lines == ["directory_refresh_failed reason=internal_error type=RuntimeError"]
    (failed,) = events(records, "directory_refresh_failed")
    assert failed["keep"]["reason"] == "internal_error"
    assert failed["error"] == {"type": "builtins.RuntimeError"}  # no message, no stack


def test_a_connection_failure_is_reported_without_its_message(cycle, capsys):
    """Requirements: REV-75 (logs); observability 4. Plan A8."""

    def refuse(settings):
        raise OSError(f"could not reach postgresql://keep:{SECRET}@{DSN_HOST}/keep")

    code = worker.main(["--once"], connect=refuse)
    out = capsys.readouterr()
    assert code == 1 and cycle[0] == []
    assert out.out.splitlines() == ["directory_refresh_failed reason=internal_error type=OSError"]
    for secret in (SECRET, DSN_HOST):
        assert secret not in out.out + out.err
    (failed,) = events(records_of(out.err), "directory_refresh_failed")
    assert failed["error"] == {"type": "builtins.OSError"}


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


# Stopping (REV-75): a run budget or SIGTERM sets the stop event.

TEAMS = [f"team{index}" for index in range(1, 7)]


def adapi(delay=0.0, on_request=None):
    """A small ADAPI: people by batch, any group by exact name, groups without members."""

    def handler(request):
        if on_request is not None:
            on_request(request)
        time.sleep(delay)
        params = parse_qs(request.url.query.decode())
        path = request.url.path
        if path == "/groups/members/user":
            return httpx.Response(200, json=[])
        if path == "/groups":
            name = params["samAccountName"][0]
            return httpx.Response(200, json=[{"sAMAccountName": name, "cn": name}])
        if path == "/users" and "customFilter" in params:
            names = re.findall(r"sAMAccountName=([^)]+)", params["customFilter"][0])
            return httpx.Response(
                200,
                json=[
                    {"sAMAccountName": n, "displayName": n.title(), "userAccountControl": "512"}
                    for n in names
                ],
            )
        return httpx.Response(200, json=[])

    return httpx.MockTransport(handler)


@pytest.fixture
def stoppable(environment):
    """Fake roots and publication around the real ADAPI reader and ``run_cycle``."""
    published = []

    def roots(conn, source, superadmin):
        found = {PrincipalKey(source, name): "user" for name in ("alice", "bob")}
        found.update({PrincipalKey(source, name): "team" for name in TEAMS})
        return found

    def publish(database, read, *, superadmin_group, bootstrap_qualified, on_accepted):
        generation = len(published) + 1
        evidence = read(generation)
        result = PublicationResult(evidence.complete, 1, (), False, False)
        published.append(sorted(key.object_id for key in evidence.roots))
        if hook[0] is not None:
            hook[0]()
        reason = None if evidence.complete else evidence.failure_reason
        return SaveOutcome(evidence, result, reason, 1)

    hook = [None]
    environment.setattr(worker, "tracked_roots", roots)
    environment.setattr(worker, "publish_with_retry", publish)
    return published, hook


def summary_of(records):
    (completed,) = events(records, "directory_refresh_completed")
    return completed["keep"]


def test_a_spent_budget_stops_reading_and_keeps_what_was_published(stoppable, capsys):
    """Requirements: REV-75 (run budget); worker scope 4. Plan A6."""
    published, _ = stoppable
    began = time.monotonic()
    code, lines, database, records = run(
        ["--once", "--budget-seconds", "1"], capsys, transport=adapi(delay=0.25)
    )
    assert time.monotonic() - began < 5
    assert code == 1 and database.closed
    # The people's unit (one batch call) finished well inside the budget.
    assert published[0] == ["alice", "bob"]
    assert "directory_root_failed root=alice reason=directory_stopped" not in lines
    failed = {line.split()[1]: line.split()[2] for line in lines[:-1]}
    assert set(failed.values()) == {"reason=directory_stopped"}
    # The last team is skipped without a read or a publication.
    assert "root=team6" in failed and ["team6"] not in published
    unpublished = {f"root={name}" for name in TEAMS} - {f"root={p[0]}" for p in published[1:]}
    assert unpublished <= set(failed)
    stopped = events(records, "directory_root_failed")
    assert {r["keep"]["reason"] for r in stopped} == {"directory_stopped"}
    totals = summary_of(records)
    assert totals["units"] == 7 and totals["failed_roots"] == len(failed)
    assert totals["published"] == 7 - len(failed)
    assert lines[-1].startswith("directory_refresh units=7 ")


def test_sigterm_finishes_the_publication_under_way_then_stops(stoppable, capsys):
    """Requirements: REV-75 (SIGTERM); worker scope 4. Plan A6."""
    published, hook = stoppable
    before = signal.getsignal(signal.SIGTERM)

    def terminate_during_the_first_team():
        if len(published) == 2:
            handler = signal.getsignal(signal.SIGTERM)
            assert handler is not before
            handler(signal.SIGTERM, None)

    hook[0] = terminate_during_the_first_team
    code, lines, _, records = run(["--once"], capsys, transport=adapi())
    assert code == 1
    assert signal.getsignal(signal.SIGTERM) is before
    # The publication that was under way completed; nothing was read after it.
    assert published == [["alice", "bob"], ["team1"]]
    assert lines == [
        *(f"directory_root_failed root={name} reason=directory_stopped" for name in TEAMS[1:]),
        "directory_refresh units=7 published=2 failed_roots=5 bootstrap_ready=false",
    ]
    assert summary_of(records)["failed_roots"] == 5


def test_a_read_cut_short_by_the_stop_reports_the_stop(stoppable, environment):
    """Requirements: REV-75 (run budget). Plan A6."""
    from keep.config import Settings

    published, _ = stoppable
    stop = worker.threading.Event()

    def stop_after_the_group_lookup(request):
        if request.url.path == "/groups" and "team2" in str(request.url):
            stop.set()

    summary = worker.refresh(
        FakeDatabase(),
        Settings(role="directory"),
        emit=lambda line: None,
        stop=stop,
        transport=adapi(on_request=stop_after_the_group_lookup),
    )
    by_root = {unit.roots[0]: unit for unit in summary.units if unit.kind == "team"}
    assert by_root["team1"].published
    # team2's members call met the stop: its attempt was recorded and reports the stop.
    assert by_root["team2"].outcome is not None and by_root["team2"].reason == "directory_stopped"
    assert all(by_root[name].outcome is None for name in TEAMS[2:])
    assert published[-1] == ["team2"]


def test_the_signal_handler_only_sets_the_stop_event():
    """Requirements: REV-75 (SIGTERM)."""
    stop = worker.threading.Event()
    assert worker.stop_on_signal(stop)(signal.SIGTERM, None) is None
    assert stop.is_set()
