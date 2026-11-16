"""Password check for sign-in: one LDAP bind, the WhoAmI check and the return path.

ldap3 is replaced by a fake connection that records what it was given, except in the
log test, which lets ldap3 itself fail against a closed local port.

Requirements: REV-73; identity configuration 2-3, 5-6; plan A3, A9, A10, A20.
"""

from __future__ import annotations

import logging
import socket
import ssl
from types import SimpleNamespace

import pytest
from ldap3 import NONE, SIMPLE, SYNC
from ldap3.core.exceptions import (
    LDAPInvalidCredentialsResult,
    LDAPOperationResult,
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
)
from ldap3.utils import log as ldap3_log

from keep.identity import login
from keep.identity.authentication import InvalidReturnPath, safe_return_path
from keep.identity.login import (
    LDAPBindConfig,
    SignInRejected,
    SignInUnavailable,
    check_password,
    whoami_names,
)

MIXED_PASSWORD = "Shalom-שלום-Keep-2026!"


class FakeConnection:
    instances: list = []

    def __init__(self, server, **options):
        self.server, self.options = server, options
        self.password = options.get("password")
        self.calls = []
        self.bind_result = True
        self.bind_error = None
        self.whoami = "u:CORP\\jdoe"
        self.whoami_error = None
        FakeConnection.instances.append(self)
        self.extend = SimpleNamespace(standard=SimpleNamespace(who_am_i=self._who_am_i))
        configure = FakeConnection.configure
        if configure:
            configure(self)

    configure = None

    def bind(self):
        self.calls.append("bind")
        if self.bind_error:
            raise self.bind_error
        return self.bind_result

    def _who_am_i(self):
        self.calls.append("who_am_i")
        if self.whoami_error:
            raise self.whoami_error
        return self.whoami

    def unbind(self):
        self.calls.append("unbind")


@pytest.fixture
def fake_ldap(monkeypatch):
    servers = []

    def server(host, **options):
        servers.append((host, options))
        return SimpleNamespace(host=host, **options)

    FakeConnection.instances = []
    FakeConnection.configure = None
    monkeypatch.setattr(login, "Connection", FakeConnection)
    monkeypatch.setattr(login, "Server", server)
    yield SimpleNamespace(servers=servers, connections=FakeConnection.instances)
    FakeConnection.configure = None


def config(**overrides):
    values = dict(host="ldap.corp.example", port=389, bind_format="{username}@corp.example")
    values.update(overrides)
    return LDAPBindConfig(**values)


def test_empty_password_never_reaches_ldap(fake_ldap):
    """Requirements: REV-73; identity configuration 2; plan A3."""
    for password in ("", None):
        with pytest.raises(SignInRejected) as refused:
            check_password(config(), "jdoe", password)
        assert refused.value.args == (login.REJECT_EMPTY_PASSWORD,)
    assert fake_ldap.connections == [] and fake_ldap.servers == []


def test_bind_uses_the_configured_format_utf8_bytes_and_timeouts(fake_ldap):
    """Requirements: REV-73; identity configuration 3; plan A9."""
    check_password(config(), "jdoe", MIXED_PASSWORD)
    [(host, server)] = fake_ldap.servers
    assert host == "ldap.corp.example"
    assert server == {
        "port": 389,
        "use_ssl": False,
        "tls": None,
        "connect_timeout": 2.0,
        "get_info": NONE,
    }
    [connection] = fake_ldap.connections
    assert connection.options["user"] == "jdoe@corp.example"
    assert connection.calls == ["bind", "who_am_i", "unbind"]
    options = connection.options
    assert options["password"] == MIXED_PASSWORD.encode("utf-8")
    assert isinstance(options["password"], bytes)
    assert options["authentication"] == SIMPLE and options["client_strategy"] == SYNC
    assert options["read_only"] is True and options["raise_exceptions"] is True
    assert options["receive_timeout"] == 2.0 and options["auto_referrals"] is False
    # The connection no longer holds the encoded password after the check.
    assert connection.password is None


def test_tls_setting_validates_the_server_certificate(tmp_path):
    """Requirements: REV-73; identity configuration 6."""
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic", encoding="utf-8")
    server = config(use_tls=True, ca_file=ca, port=636).server()
    assert server.ssl is True and server.port == 636
    assert server.tls.validate == ssl.CERT_REQUIRED
    assert server.tls.ca_certs_file == str(ca)
    plain = config().server()
    assert plain.ssl is False


def test_configuration_requires_host_format_and_an_existing_ca(tmp_path):
    """Requirements: REV-73; identity configuration 3, 6."""
    settings = SimpleNamespace(
        ldap_host=None,
        ldap_port=389,
        ldap_bind_format="{username}@corp.example",
        ldap_use_tls=False,
        ldap_ca_file=None,
    )
    with pytest.raises(ValueError):
        LDAPBindConfig.from_settings(settings)
    settings.ldap_host = "ldap.corp.example"
    assert LDAPBindConfig.from_settings(settings).bind_user("jdoe") == "jdoe@corp.example"
    for bad in ("corp\\user", "{username}{username}", "{username}@{domain}"):
        with pytest.raises(ValueError):
            config(bind_format=bad)
    with pytest.raises(ValueError):
        config(use_tls=True, ca_file=tmp_path / "missing.pem")
    with pytest.raises(ValueError):
        config(port=0)


@pytest.mark.parametrize(
    ("authzid", "accepted"),
    [
        ("u:CORP\\jdoe", True),
        ("u:corp\\JDoe", True),
        ("u:OTHER-DOMAIN\\jdoe", True),
        ("u:CORP\\other", False),
        ("u:jdoe", False),
        ("u:\\jdoe", False),
        ("u:CORP\\x\\jdoe", False),
        ("u:CORP\\", False),
        ("dn:uid=jdoe,ou=people,dc=keep,dc=local", True),
        ("dn:UID=JDOE,OU=people,DC=keep,DC=local", True),
        ("dn:uid=other,ou=people,dc=keep,dc=local", False),
        ("dn:", False),
        ("", False),
        (None, False),
        ("jdoe", False),
        ("U:CORP\\jdoe", False),
    ],
)
def test_whoami_must_name_the_typed_username(authzid, accepted):
    """Requirements: REV-73; identity configuration 3; plan A20."""
    assert whoami_names(authzid, "jdoe", "uid=jdoe,ou=people,dc=keep,dc=local") is accepted


def test_whoami_naming_someone_else_is_refused_after_the_bind(fake_ldap):
    """Requirements: REV-73; identity configuration 3; plan A20."""
    FakeConnection.configure = lambda c: setattr(c, "whoami", "u:CORP\\other")
    with pytest.raises(SignInRejected) as refused:
        check_password(config(), "jdoe", "secret-Pass-1")
    assert refused.value.args == (login.REJECT_IDENTITY_MISMATCH,)
    assert fake_ldap.connections[0].calls == ["bind", "who_am_i", "unbind"]
    FakeConnection.configure = lambda c: setattr(c, "whoami", "u:CORP\\jdoe")
    check_password(config(), "jdoe", "secret-Pass-1")
    FakeConnection.configure = lambda c: setattr(c, "whoami", None)
    with pytest.raises(SignInRejected):
        check_password(config(), "jdoe", "secret-Pass-1")


@pytest.mark.parametrize(
    ("error", "expected", "reason"),
    [
        (LDAPInvalidCredentialsResult(result=49), SignInRejected, login.REJECT_CREDENTIALS),
        (LDAPOperationResult(result=53), SignInRejected, login.REJECT_CREDENTIALS),
        (LDAPOperationResult(result=51), SignInUnavailable, login.UNAVAILABLE_LDAP_RESULT),
        (LDAPOperationResult(result=52), SignInUnavailable, login.UNAVAILABLE_LDAP_RESULT),
        (LDAPSocketOpenError("refused"), SignInUnavailable, login.UNAVAILABLE_LDAP),
        (LDAPSocketReceiveError("timed out"), SignInUnavailable, login.UNAVAILABLE_LDAP),
        (TimeoutError(), SignInUnavailable, login.UNAVAILABLE_LDAP),
    ],
)
def test_bind_errors_map_to_rejected_or_unavailable(fake_ldap, error, expected, reason):
    """Requirements: REV-73; identity configuration 3, 9; plan A2, A5."""
    FakeConnection.configure = lambda c: setattr(c, "bind_error", error)
    with pytest.raises(expected) as failure:
        check_password(config(), "jdoe", "secret-Pass-1")
    assert failure.value.args == (reason,)
    assert "secret-Pass-1" not in repr(failure.value)
    assert failure.value.__cause__ is None and failure.value.__suppress_context__
    assert fake_ldap.connections[0].calls == ["bind", "unbind"]


def test_unbound_result_and_whoami_failure_are_unavailable(fake_ldap):
    """Requirements: REV-73; identity configuration 3, 9; plan A5."""
    FakeConnection.configure = lambda c: setattr(c, "bind_result", False)
    with pytest.raises(SignInUnavailable):
        check_password(config(), "jdoe", "secret-Pass-1")
    FakeConnection.configure = lambda c: setattr(c, "whoami_error", LDAPOperationResult(result=2))
    with pytest.raises(SignInUnavailable):
        check_password(config(), "jdoe", "secret-Pass-1")


def _closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_password_never_appears_in_logs_even_with_ldap3_logging_on(caplog):
    """Requirements: REV-73; identity configuration 3, 13; plan A10."""
    password = "Visible-סיסמה-" + "x7Q"
    previous = (
        ldap3_log.get_library_log_detail_level(),
        ldap3_log.get_library_log_activation_lavel(),
        ldap3_log.get_library_log_hide_sensitive_data(),
    )
    # A deployment could turn ldap3's own logging all the way up; the check still
    # makes it strip credentials.
    ldap3_log.set_library_log_hide_sensitive_data(False)
    ldap3_log.set_library_log_activation_level(logging.DEBUG)
    ldap3_log.set_library_log_detail_level(ldap3_log.EXTENDED)
    try:
        with caplog.at_level(logging.DEBUG):
            with caplog.at_level(logging.DEBUG, logger="ldap3"):
                with pytest.raises(SignInUnavailable) as failure:
                    check_password(config(host="127.0.0.1", port=_closed_port()), "jdoe", password)
    finally:
        ldap3_log.set_library_log_detail_level(previous[0])
        ldap3_log.set_library_log_activation_level(previous[1])
        ldap3_log.set_library_log_hide_sensitive_data(previous[2])
    text = "\n".join(
        record.getMessage() + repr(record.args) + str(record.exc_info) for record in caplog.records
    )
    assert any(record.name == "ldap3" for record in caplog.records)
    for form in (password, password.encode("utf-8").decode("latin-1"), repr(password.encode())):
        assert form not in text
    assert password not in repr(failure.value) and password not in str(failure.value)


@pytest.mark.parametrize(
    "path",
    ["https://evil.example", "//evil.example", "/\\evil", "/%2fevil", "/%255cevil", "/\nlocation"],
)
def test_return_paths_reject_browser_normalization_attacks(path):
    """Requirements: REV-73; identity configuration 2."""
    with pytest.raises(InvalidReturnPath):
        safe_return_path(path)


def test_local_return_paths_are_kept():
    """Requirements: REV-73; identity configuration 2."""
    assert safe_return_path("/tenants/a/alerts?view=open") == "/tenants/a/alerts?view=open"
    with pytest.raises(InvalidReturnPath):
        safe_return_path("/" + "a" * 2048)
