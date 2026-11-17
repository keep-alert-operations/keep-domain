"""ADAPI client and directory reader against an in-memory ADAPI (httpx.MockTransport).

Requirements: REV-73; REV-76; identity configuration 2, 6-7; plan "ADAPI client" and
"Directory protocol on ADAPI", A13, A25; plan (REV-75/76) B2 and B9.
"""

import json
import threading
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from keep import request_budget
from keep.identity.adapi import (
    REQUEST_CALL_CAP,
    ADAPIClient,
    ADAPIConfig,
    ADAPIDirectoryReader,
    InvalidUsername,
    batch_filter,
    call_timeout,
    escape_filter_value,
    job_verification_deadline,
    normalize_username,
    principal_key,
    user_evidence,
    verify_root,
    verify_roots,
)
from keep.identity.directory import (
    FAILURE_DEADLINE,
    FAILURE_TOO_LARGE,
    FAILURE_UNAVAILABLE,
    DirectoryUnavailable,
    PrincipalKey,
)

CLIENT_ID = "test-client-id-secret"
CONFIG = ADAPIConfig("https://adapi.test/api", CLIENT_ID, lookup_batch=50)


def key(name):
    return PrincipalKey("adapi", name)


class FakeADAPI:
    """Exact samAccountName, sAMAccountName customFilter batches and recursive members.

    ``/users/user`` answers an exact samAccountName with the matching rows (REV-76),
    the same rows ``/users`` returns for it. Rows keep ADAPI's userAccountControl,
    which Keep no longer requests or reads.
    """

    def __init__(self):
        self.users = {}
        self.groups = {}
        self.members = {}
        self.requests = []
        self.status = {}
        self.omit = set()
        self.duplicates = set()
        self.timeouts = []

    def user(self, name, display=None, uac="512"):
        self.users.setdefault(name.lower(), []).append(
            {
                "sAMAccountName": name,
                "displayName": display or name.title(),
                "userAccountControl": uac,
                "cn": name,
            }
        )

    def group(self, name, members=(), display=None, cn=None):
        self.groups.setdefault(name.lower(), []).append(
            {
                "sAMAccountName": name,
                "cn": cn or name,
                **({"displayName": display} if display else {}),
            }
        )
        self.members[name.lower()] = list(members)

    def __call__(self, request):
        url = urlsplit(str(request.url))
        query = parse_qs(url.query)
        route = url.path.removeprefix("/api")
        self.requests.append((route, query, {"clientid": request.headers.get("ClientId")}))
        self.timeouts.append(request.extensions.get("timeout", {}).get("read"))
        if route in self.status:
            return httpx.Response(self.status[route], text="Server error naming local-admin")
        if request.headers.get("ClientId") != CLIENT_ID:
            return httpx.Response(401)
        if route == "/groups/members/user":
            assert query["isRecursive"] == ["true"]
            names = self.members.get(query["samAccountName"][0].lower(), [])
            rows = [
                {
                    "sAMAccountName": r["sAMAccountName"],
                    "userAccountControl": r["userAccountControl"],
                    "distinguishedName": "CN=x",
                    "objectGUID": "g",
                }
                for n in names
                for r in self.users.get(n.lower(), [])
            ]
            return httpx.Response(200, json=rows)
        if route == "/users/user":
            assert "customFilter" not in query and len(query["samAccountName"]) == 1
        table = self.users if route in ("/users", "/users/user") else self.groups
        rows = []
        if "samAccountName" in query:
            rows = list(table.get(query["samAccountName"][0].lower(), []))
        elif "customFilter" in query:
            text = query["customFilter"][0]
            assert text.startswith("(|") and text.endswith(")")
            names = [part.split("=", 1)[1] for part in text[2:-1].strip("()").split(")(")]
            for name in names:
                plain = name.replace("\\28", "(").replace("\\29", ")").replace("\\2a", "*")
                plain = plain.replace("\\5c", "\\")
                if plain.lower() in self.omit:
                    continue
                rows.extend(table.get(plain.lower(), []))
                if plain.lower() in self.duplicates:
                    rows.extend(table.get(plain.lower(), []))
        return httpx.Response(200, json=rows)


@pytest.fixture
def adapi():
    fake = FakeADAPI()
    for name, uac in (("alice", "512"), ("bob", "514"), ("carol", "512")):
        fake.user(name, uac=uac)
    fake.user("WS-0001$")
    fake.group("team-a", ["alice", "bob", "WS-0001$"], cn="Team A")
    return fake


def client(adapi, **options):
    return ADAPIClient(CONFIG, call_cap=5.0, transport=httpx.MockTransport(adapi), **options)


def test_escape_filter_value_follows_rfc4515():
    assert escape_filter_value("x)(objectClass=*") == "x\\29\\28objectClass=\\2a"
    assert escape_filter_value("a\\b*c(d)\x00") == "a\\5cb\\2ac\\28d\\29\\00"
    assert batch_filter(["a(1)", "b"]) == "(|(sAMAccountName=a\\281\\29)(sAMAccountName=b))"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "a" * 65,
        "a@b",
        "a\\b",
        "a*",
        "a/b",
        "a[b",
        "a]b",
        "a:b",
        "a;b",
        "a|b",
        "a=b",
        "a,b",
        "a+b",
        "a?b",
        "a<b",
        "a>b",
        'a"b',
        "a\x00b",
        "a\nb",
        "a\x7fb",
        "a\x85b",
    ],
)
def test_normalize_username_refuses_forbidden_names(bad):
    with pytest.raises(InvalidUsername):
        normalize_username(bad)
    assert issubclass(InvalidUsername, ValueError)


def test_normalize_username_trims_and_lowercases():
    assert normalize_username("  J.Doe-1 ") == "j.doe-1"
    assert normalize_username("a" * 64) == "a" * 64
    assert normalize_username("משה") == "משה"
    assert principal_key("ALICE") == key("alice")


def test_client_id_header_and_repeated_attributes(adapi):
    """Sign-in's exact person lookup calls ``/users/user`` with the ``/users`` params.

    Requirements: REV-76; identity configuration 6; plan B2 (no userAccountControl)
    and B9.
    """
    with client(adapi) as c:
        rows = c.lookup_user_rows(" Alice ")
    route, query, headers = adapi.requests[0]
    assert route == "/users/user" and query["samAccountName"] == ["alice"]
    assert query["attributesToLoad"] == ["sAMAccountName", "displayName"]
    assert headers["clientid"] == CLIENT_ID
    assert len(rows) == 1 and c.calls == 1
    assert CLIENT_ID not in repr(CONFIG)


def test_sign_in_rows_tell_zero_one_and_many_apart(adapi):
    adapi.user("dup")
    adapi.user("dup")
    with client(adapi) as c:
        assert c.lookup_user_rows("nobody") == []
        assert len(c.lookup_user_rows("dup")) == 2


@pytest.mark.parametrize("status", [401, 404, 500, 503])
def test_non_200_is_unavailable_with_a_sanitized_reason(adapi, status):
    adapi.status["/users"] = status
    with client(adapi) as c, pytest.raises(DirectoryUnavailable) as raised:
        c.find_users([("samAccountName", "alice")])
    assert raised.value.args == ("directory_status_rejected",)
    assert "local-admin" not in str(raised.value) and CLIENT_ID not in str(raised.value)


@pytest.mark.parametrize("body", [b"not json", b'{"rows": []}', b"[1, 2]"])
def test_bad_json_or_non_array_is_unavailable(body):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    with ADAPIClient(CONFIG, call_cap=5.0, transport=transport) as c:
        with pytest.raises(DirectoryUnavailable) as raised:
            c.find_groups([("samAccountName", "x")])
    assert raised.value.args == ("directory_response_invalid",)


def test_transport_timeout_is_unavailable_without_text():
    def slow(request):
        raise httpx.ReadTimeout("timed out reading https://adapi.test/users?samAccountName=alice")

    with ADAPIClient(CONFIG, call_cap=5.0, transport=httpx.MockTransport(slow)) as c:
        with pytest.raises(DirectoryUnavailable) as raised:
            c.find_users([("samAccountName", "alice")])
    assert raised.value.args == ("directory_timeout",)


def test_each_call_takes_the_budgeted_timeout(adapi):
    with client(adapi) as c:
        c.find_users([("samAccountName", "alice")])
    assert adapi.timeouts[-1] == 5.0
    assert call_timeout(REQUEST_CALL_CAP) == 3.0
    with request_budget.request_budget(2.5):
        assert 1.0 < call_timeout(REQUEST_CALL_CAP) <= 1.5
        with ADAPIClient(CONFIG, call_cap=3.0, transport=httpx.MockTransport(adapi)) as c:
            c.find_users([("samAccountName", "alice")])
        assert adapi.timeouts[-1] <= 1.5
    with request_budget.request_budget(80):
        assert job_verification_deadline() == 60
    with request_budget.request_budget(40):
        assert 24 < job_verification_deadline() <= 25
    with request_budget.request_budget(0.5), pytest.raises(DirectoryUnavailable) as raised:
        call_timeout(REQUEST_CALL_CAP)
    assert raised.value.args == ("directory_deadline",)


def test_stop_event_is_checked_before_every_call(adapi):
    stop = threading.Event()
    with client(adapi, stop=stop) as c:
        c.find_users([("samAccountName", "alice")])
        stop.set()
        with pytest.raises(DirectoryUnavailable) as raised:
            c.find_users([("samAccountName", "alice")])
    assert raised.value.args == ("directory_stopped",) and c.calls == 1


def test_kind_hint_asks_the_hinted_endpoint_first(adapi):
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("team-a"): "team"})
        group = reader.lookup(key("team-a"))
        person = reader.lookup(key("alice"))
    assert [r[0] for r in adapi.requests] == ["/groups", "/users/user"]
    assert group.kind == "team" and group.label == "Team A" and group.eligible
    assert person.kind == "user" and person.label == "Alice" and person.eligible


def test_wrong_hint_falls_back_to_the_other_endpoint(adapi):
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("alice"): "team"})
        obj = reader.lookup(key("alice"))
    assert [r[0] for r in adapi.requests] == ["/groups", "/users/user"]
    assert obj.kind == "user"


def test_group_label_prefers_display_name_then_cn(adapi):
    adapi.group("named", display="Named Group", cn="named-cn")
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("named"): "team"})
        assert reader.lookup(key("named")).label == "Named Group"


def test_a_missing_person_is_not_negated_and_a_missing_group_tombstones(adapi):
    """Not found only when both endpoints are empty; only the group is a negative fact.

    Requirements: REV-76; identity configuration 6 and 8; plan B2. Publication
    skipping the person is checked against PostgreSQL in delivery.
    """
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("gone-team"): "team"})
        group = reader.lookup(key("gone-team"))
        person = reader.lookup(key("gone-person"))
    assert group.deleted and not group.eligible and group.kind == "team"
    assert person.deleted and not person.eligible and person.kind == "user"
    assert [r[0] for r in adapi.requests] == ["/groups", "/users/user", "/users/user", "/groups"]
    evidence = verify_roots(
        CONFIG,
        {key("gone-team"): "team", key("gone-person"): "user", key("alice"): "user"},
        4,
        deadline_seconds=60,
        call_cap=5,
        transport=httpx.MockTransport(adapi),
    )
    assert evidence.complete and evidence.failure_reason is None
    assert evidence.negative_keys == {key("gone-team")}
    assert evidence.objects[key("gone-person")].deleted
    assert evidence.memberships[key("gone-person")] == frozenset()
    assert evidence.memberships[key("alice")] == {key("alice")}
    adapi.requests.clear()
    adapi.status["/users/user"] = 500
    with client(adapi) as c, pytest.raises(DirectoryUnavailable):
        ADAPIDirectoryReader(c, hints={key("gone-team"): "team"}).lookup(key("gone-team"))


def test_a_uac_of_514_is_ignored(adapi):
    """A disabled account (UAC 514) is an eligible person; an odd UAC fails nothing.

    Requirements: REV-76; identity configuration 6; plan B2.
    """
    adapi.user("odd", uac="not a number")
    adapi.users["nouac"] = [{"sAMAccountName": "nouac", "displayName": "No UAC"}]
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c)
        bob, odd, nouac = (reader.lookup(key(n)) for n in ("bob", "odd", "nouac"))
    assert bob.eligible and not bob.deleted and bob.label == "Bob"
    assert odd.eligible and nouac.eligible and nouac.label == "No UAC"
    assert all(
        "userAccountControl" not in q.get("attributesToLoad", []) for _, q, _ in adapi.requests
    )


def test_two_rows_are_ambiguous(adapi):
    adapi.user("alice")
    with client(adapi) as c, pytest.raises(DirectoryUnavailable) as raised:
        ADAPIDirectoryReader(c).lookup(key("alice"))
    assert raised.value.args == ("directory_ambiguous",)


def test_returned_name_must_equal_the_key(adapi):
    adapi.users["mallory"] = [{"sAMAccountName": "alice", "userAccountControl": "512"}]
    with client(adapi) as c, pytest.raises(DirectoryUnavailable) as raised:
        ADAPIDirectoryReader(c).lookup(key("mallory"))
    assert raised.value.args == ("directory_identity_mismatch",)


def test_members_skip_computers_and_batch_names(adapi):
    names = [f"user{i:03d}" for i in range(120)]
    for name in names:
        adapi.user(name)
    adapi.group("big", names + ["WS-0001$"])
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("big"): "team"})
        members = list(reader.members(key("big")))
        calls = c.calls
        looked = [reader.lookup(m) for m in members]
        assert c.calls == calls
    assert members == [key(n) for n in names]
    batches = [q for route, q, _ in adapi.requests if route == "/users"]
    assert len(batches) == 3
    for query in batches:
        assert query["customFilter"][0].count("(sAMAccountName=") <= 50
        assert query["attributesToLoad"] == ["sAMAccountName", "displayName"]
    assert all(obj.label.startswith("User") for obj in looked)


def test_member_omitted_by_batch_is_an_eligible_person_by_name(adapi):
    """Requirements: REV-73; REV-76 (no disabled state from the members route)."""
    adapi.omit = {"bob"}
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("team-a"): "team"})
        members = list(reader.members(key("team-a")))
        bob = reader.lookup(key("bob"))
    assert members == [key("alice"), key("bob")]
    assert bob.label == "bob" and bob.eligible and not bob.deleted


def test_member_names_are_escaped_in_batches(adapi):
    adapi.user("o(dd)")
    adapi.group("odd", ["o(dd)"])
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("odd"): "team"})
        list(reader.members(key("odd")))
    query = adapi.requests[-1][1]
    assert query["customFilter"] == ["(|(sAMAccountName=o\\28dd\\29))"]
    assert reader.lookup(key("o(dd)")).label == "O(Dd)"


def test_oversized_group_fails_before_name_batches(adapi):
    names = [f"m{i}" for i in range(11)]
    for name in names:
        adapi.user(name)
    adapi.group("huge", names)
    with client(adapi) as c:
        reader = ADAPIDirectoryReader(c, hints={key("huge"): "team"}, max_objects=10)
        with pytest.raises(DirectoryUnavailable) as raised:
            list(reader.members(key("huge")))
    assert raised.value.args == ("directory_allocation_exceeded",)
    assert [r[0] for r in adapi.requests] == ["/groups/members/user"]


def test_prefetch_batches_user_roots_and_proves_absence_exactly(adapi):
    """Requirements: REV-73; REV-76 (a person not found is not a negative fact); B9."""
    names = [f"p{i:03d}" for i in range(101)]
    for name in names:
        adapi.user(name)
    roots = {key(n): "user" for n in names + ["gone"]}
    evidence = verify_roots(
        CONFIG,
        roots,
        7,
        deadline_seconds=60,
        call_cap=5,
        transport=httpx.MockTransport(adapi),
    )
    assert evidence.complete and evidence.generation == 7
    routes = [r[0] for r in adapi.requests]
    assert routes.count("/users") == 3 and routes.count("/users/user") == 1
    assert routes.count("/groups") == 1
    assert evidence.objects[key("gone")].deleted
    assert evidence.negative_keys == frozenset()


def test_verify_root_reads_a_group_with_flattened_edges(adapi):
    evidence = verify_root(
        CONFIG,
        "Team-A",
        "team",
        3,
        deadline_seconds=7,
        call_cap=REQUEST_CALL_CAP,
        transport=httpx.MockTransport(adapi),
    )
    assert evidence.complete and evidence.failure_reason is None
    assert evidence.roots == {key("team-a")}
    assert evidence.edges == {key("team-a"): {key("alice"), key("bob")}}
    # REV-76: bob's UAC 514 no longer removes him from the group.
    assert evidence.memberships[key("team-a")] == {key("alice"), key("bob")}
    assert len(adapi.requests) == 3


def test_verify_reports_structured_reasons(adapi):
    adapi.status["/groups/members/user"] = 500
    unavailable = verify_root(
        CONFIG,
        "team-a",
        "team",
        1,
        deadline_seconds=7,
        call_cap=3,
        transport=httpx.MockTransport(adapi),
    )
    assert not unavailable.complete and unavailable.failure_reason == FAILURE_UNAVAILABLE
    del adapi.status["/groups/members/user"]
    too_large = verify_root(
        CONFIG,
        "team-a",
        "team",
        2,
        deadline_seconds=7,
        call_cap=3,
        max_objects=2,
        transport=httpx.MockTransport(adapi),
    )
    assert too_large.failure_reason == FAILURE_TOO_LARGE
    stop = threading.Event()
    stop.set()
    stopped = verify_root(
        CONFIG,
        "team-a",
        "team",
        3,
        deadline_seconds=7,
        call_cap=3,
        stop=stop,
        transport=httpx.MockTransport(adapi),
    )
    assert stopped.failure_reason == FAILURE_UNAVAILABLE
    with request_budget.request_budget(0.9):
        late = verify_root(
            CONFIG,
            "team-a",
            "team",
            4,
            deadline_seconds=7,
            call_cap=3,
            transport=httpx.MockTransport(adapi),
        )
    assert late.failure_reason == FAILURE_DEADLINE
    for evidence in (unavailable, too_large, stopped, late):
        assert "local-admin" not in repr(evidence.failures)


def test_prefetch_failure_returns_incomplete_evidence(adapi):
    adapi.status["/users"] = 503
    evidence = verify_roots(
        CONFIG,
        {key("alice"): "user", key("carol"): "user"},
        9,
        deadline_seconds=60,
        call_cap=5,
        transport=httpx.MockTransport(adapi),
    )
    assert not evidence.complete and evidence.failure_reason == FAILURE_UNAVAILABLE
    assert evidence.objects == {} and evidence.roots == {key("alice"), key("carol")}


def test_user_evidence_from_a_sign_in_row():
    """Requirements: REV-76; identity configuration 3 (sign-in evidence); plan B3."""
    row = {"sAMAccountName": "Alice", "displayName": "Alice A", "userAccountControl": "514"}
    evidence = user_evidence("adapi", row, 5, datetime.now(UTC))
    assert evidence.complete and evidence.roots == {key("alice")}
    assert evidence.objects[key("alice")].eligible
    assert evidence.memberships == {key("alice"): {key("alice")}}
    assert evidence.negative_keys == frozenset()
    assert json.dumps(evidence.semantic_digest)


def test_config_validates_origin_and_reads_settings():
    with pytest.raises(ValueError):
        ADAPIConfig("https://user:pw@adapi.test", CLIENT_ID)
    with pytest.raises(ValueError):
        ADAPIConfig("https://adapi.test", "")
    from types import SimpleNamespace

    from pydantic import SecretStr

    settings = SimpleNamespace(
        adapi_url="http://127.0.0.1:58092", adapi_client_id=SecretStr("x"), adapi_lookup_batch=25
    )
    config = ADAPIConfig.from_settings(settings)
    assert config.lookup_batch == 25 and config.source == "adapi"
