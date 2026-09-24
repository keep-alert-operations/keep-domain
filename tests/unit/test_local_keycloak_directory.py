from contextlib import contextmanager
import json
import ssl
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest

from appchi.identity.directory import DirectoryUnavailable, DirectoryVerifier, PrincipalKey
from appchi.identity.keycloak_directory import (
    KeycloakDirectoryReader,
    LocalKeycloakConfig,
    load_config,
)
from appchi.identity import local_keycloak_worker


def uid(number):
    return str(UUID(int=number))


@pytest.fixture
def config(monkeypatch):
    monkeypatch.setenv("APPCHI_ENVIRONMENT", "development")
    monkeypatch.setenv("APPCHI_LOCAL_DIRECTORY_SECRET", "test-secret")
    context = ssl.create_default_context()
    monkeypatch.setattr(
        "appchi.identity.keycloak_directory.ssl.create_default_context", lambda **_: context
    )
    return LocalKeycloakConfig(
        issuer="https://localhost:58443/realms/appchi-local",
        source="keycloak-local",
        client_id="appchi-directory",
        client_secret_env="APPCHI_LOCAL_DIRECTORY_SECRET",
        ca_file="trusted-local.pem",
        superadmin_group=uid(10),
        max_objects=50,
        page_size=2,
        max_pages=100,
        local_only=True,
    )


class Realm:
    def __init__(self):
        self.users = [
            {"id": uid(1), "username": "admin", "enabled": True},
            {"id": uid(2), "username": "disabled", "enabled": False},
            {
                "id": uid(3),
                "username": "service-account",
                "enabled": True,
                "serviceAccountClientId": "appchi-directory",
            },
        ]
        self.groups = [{"id": uid(10), "name": "admins"}]
        self.children = {uid(10): [{"id": uid(11), "name": "nested"}], uid(11): []}
        self.members = {uid(10): [self.users[1]], uid(11): [self.users[0]]}
        self.fail = None
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        if request.method == "POST":
            assert request.url.path.endswith("/protocol/openid-connect/token")
            assert b"grant_type=client_credentials" in request.content
            return httpx.Response(200, json={"access_token": "test-token"})
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer test-token"
        path = request.url.path.removeprefix("/admin/realms/appchi-local")
        if path == self.fail:
            return httpx.Response(503, text="sensitive upstream failure")
        if path == "/users":
            rows = self.users
        elif path == "/groups":
            rows = self.groups
        elif path.endswith("/children"):
            rows = self.children[path.split("/")[2]]
        elif path.endswith("/members"):
            rows = self.members[path.split("/")[2]]
        else:
            return httpx.Response(404)
        first, limit = int(request.url.params["first"]), int(request.url.params["max"])
        return httpx.Response(200, json=rows[first : first + limit])


def test_complete_pagination_nested_members_disabled_and_service_accounts(config):
    realm = Realm()
    with KeycloakDirectoryReader(config, transport=httpx.MockTransport(realm)) as reader:
        roots = reader.load()
        evidence = DirectoryVerifier(reader).verify(roots, 1)
    assert evidence.complete
    assert len(roots) == 4
    group, user, disabled = [PrincipalKey(config.source, uid(n)) for n in (10, 1, 2)]
    assert evidence.memberships[group] == frozenset({user})
    assert evidence.negative_keys == frozenset({disabled})
    assert any(call.url.params.get("first") == "2" for call in realm.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "http://localhost:58443/realms/appchi-local"),
        ("issuer", "https://company.example/realms/appchi-local"),
        ("issuer", "https://localhost:58443/realms/appchi"),
        ("issuer", "https://user:secret@localhost/realms/appchi-local"),
        ("source", "ldap"),
        ("local_only", False),
        ("page_size", 0),
        ("max_objects", True),
        ("superadmin_group", "admins"),
    ],
)
def test_configuration_cannot_be_used_as_production_adapter(config, field, value):
    with pytest.raises(ValueError):
        LocalKeycloakConfig.model_validate({**config.model_dump(), field: value})


@pytest.mark.parametrize("environment", [None, "staging", "production"])
def test_explicit_development_required(config, monkeypatch, environment):
    if environment is None:
        monkeypatch.delenv("APPCHI_ENVIRONMENT")
    else:
        monkeypatch.setenv("APPCHI_ENVIRONMENT", environment)
    with pytest.raises(ValueError, match="development"):
        KeycloakDirectoryReader(config)


def test_config_secrets_are_only_environment_bindings(config, tmp_path, monkeypatch):
    path = tmp_path / "directory.json"
    path.write_text(json.dumps(config.model_dump()))
    assert load_config(path) == config
    monkeypatch.delenv("APPCHI_LOCAL_DIRECTORY_SECRET")
    with pytest.raises(ValueError, match="secret binding"):
        load_config(path)


@pytest.mark.parametrize("failure", ["duplicate", "pagination", "object_limit", "missing_member"])
def test_incomplete_or_ambiguous_traversal_never_succeeds(config, failure):
    realm = Realm()
    if failure == "duplicate":
        realm.users[1] = realm.users[0]
    elif failure == "pagination":
        config = config.model_copy(update={"max_pages": 1})
    elif failure == "object_limit":
        config = config.model_copy(update={"max_objects": 1})
    else:
        realm.members[uid(11)] = [{"id": uid(99), "username": "unknown", "enabled": True}]
    with KeycloakDirectoryReader(config, transport=httpx.MockTransport(realm)) as reader:
        with pytest.raises(DirectoryUnavailable):
            reader.load()


def test_missing_identity_requires_explicit_user_and_group_absence(config):
    realm = Realm()
    key = PrincipalKey(config.source, uid(99))
    with KeycloakDirectoryReader(config, transport=httpx.MockTransport(realm)) as reader:
        reader.load()
        assert reader.lookup(key).deleted
    paths = [r.url.path for r in realm.calls]
    assert any(path.endswith("/users/" + uid(99)) for path in paths)
    assert any(path.endswith("/groups/" + uid(99)) for path in paths)


def test_changed_enabled_state_during_membership_read_fails(config):
    realm = Realm()
    realm.members[uid(11)] = [{**realm.users[0], "enabled": False}]
    with KeycloakDirectoryReader(config, transport=httpx.MockTransport(realm)) as reader:
        with pytest.raises(DirectoryUnavailable):
            reader.load()
        assert not reader.objects[PrincipalKey(config.source, uid(1))].eligible


def test_failed_refresh_preserves_verified_negative_without_empty_success(config, monkeypatch):
    class Connection:
        def execute(self, *_):
            return self

        def fetchall(self):
            return []

    class Database:
        @contextmanager
        def transaction(self):
            yield Connection()

    received = []
    monkeypatch.setattr(local_keycloak_worker, "allocate_generation", lambda _: 4)

    def publish(conn, evidence, **kwargs):
        received.append((evidence, kwargs))
        return SimpleNamespace(accepted=False)

    monkeypatch.setattr(local_keycloak_worker, "publish", publish)
    realm = Realm()
    realm.fail = "/groups"
    evidence, _ = local_keycloak_worker.run_cycle(
        Database(), config, bootstrap=True, transport=httpx.MockTransport(realm)
    )
    assert not evidence.complete
    assert evidence.negative_keys == frozenset({PrincipalKey(config.source, uid(2))})
    assert evidence.memberships == {}
    assert received[0][1]["bootstrap_qualified"] is True
    assert "sensitive" not in repr(evidence)
