"""Password check for Keep sign-in: one LDAP simple bind and a WhoAmI check.

Requirements: REV-73; identity configuration 2-3, 6; plan "Login API", A3, A9, A10, A20.

Keep uses LDAP only to check a password with the person's own bind. It has no
service account and runs no searches. The bind runs in a worker thread (the caller
uses a thread pool) with a 2-second connect and a 2-second receive timeout:
``Server(host, port, use_ssl=<setting>, connect_timeout=2)``, then a read-only
``Connection`` as ``KEEP_LDAP_BIND_FORMAT`` filled with the username, the password as
UTF-8 bytes, ``bind()``, ``extend.standard.who_am_i()`` and ``unbind()``.

The password is used for that one bind only. It is never logged, put in an exception
message, returned or stored. Errors carry fixed reason codes. ldap3's own logging is
off unless a deployment turns it on; this module makes ldap3 strip credentials from
whatever it logs.

AD resolves ``name@domain`` by an explicit userPrincipalName before
``sAMAccountName@domain``, so the bound account can differ from the one Keep looks
up. The WhoAmI answer must name the typed username (``u:DOMAIN\\name``) or equal the
bind DN (``dn:...``, the local OpenLDAP form); anything else is refused.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ldap3 import NONE, SIMPLE, SYNC, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException, LDAPOperationResult
from ldap3.utils.log import (
    get_library_log_hide_sensitive_data,
    set_library_log_hide_sensitive_data,
)

CONNECT_TIMEOUT = 2.0
RECEIVE_TIMEOUT = 2.0

# Fixed reason codes, logged without the password. Rejections answer 401
# ``authentication_rejected``; unavailability answers 503 ``sign_in_unavailable``.
REJECT_EMPTY_PASSWORD = "empty_password"
REJECT_CREDENTIALS = "invalid_credentials"
REJECT_IDENTITY_MISMATCH = "whoami_mismatch"
UNAVAILABLE_LDAP = "ldap_unavailable"
UNAVAILABLE_LDAP_RESULT = "ldap_result_unexpected"
UNAVAILABLE_CONFIGURATION = "ldap_configuration_invalid"

# Bind results that answer this credential (refuse it) rather than say the directory
# is unavailable: inappropriateAuthentication, invalidCredentials (AD also reports
# locked, expired and disabled accounts this way), insufficientAccessRights and
# unwillingToPerform. Any other result, transport error or timeout means unavailable.
_REJECTING_RESULTS = frozenset({48, 49, 50, 53})


class SignInRejected(Exception):
    """The password, or the account it bound as, is refused. ``args[0]`` is a reason code."""


class SignInUnavailable(Exception):
    """No trustworthy answer from LDAP. ``args[0]`` is a reason code."""


def _hide_credentials() -> None:
    # ldap3 logs nothing unless its detail level is raised; if a deployment raises
    # it, bind requests and connection reprs are logged with credentials stripped.
    if not get_library_log_hide_sensitive_data():
        set_library_log_hide_sensitive_data(True)


_hide_credentials()


@dataclass(frozen=True)
class LDAPBindConfig:
    """Where and how to bind: ``KEEP_LDAP_HOST``, ``_PORT``, ``_USE_TLS``, ``_CA_FILE``
    and ``_BIND_FORMAT`` (for example ``{username}@corp.example``)."""

    host: str
    port: int
    bind_format: str
    use_tls: bool = False
    ca_file: Path | None = None
    connect_timeout: float = CONNECT_TIMEOUT
    receive_timeout: float = RECEIVE_TIMEOUT

    def __post_init__(self) -> None:
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("The LDAP host is required")
        if not 1 <= self.port <= 65535:
            raise ValueError("The LDAP port must be a TCP port")
        rest = self.bind_format.replace("{username}", "")
        if self.bind_format.count("{username}") != 1 or "{" in rest or "}" in rest:
            raise ValueError("The LDAP bind format must contain {username} exactly once")
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise ValueError("The LDAP CA file does not exist")
        if not 0 < self.connect_timeout <= 10 or not 0 < self.receive_timeout <= 10:
            raise ValueError("Invalid LDAP timeouts")

    @classmethod
    def from_settings(cls, settings: Any) -> LDAPBindConfig:
        """From Settings; ValueError when the host or bind format is missing or invalid."""
        if not settings.ldap_host or not settings.ldap_bind_format:
            raise ValueError("The LDAP host and bind format are required")
        return cls(
            settings.ldap_host,
            settings.ldap_port,
            settings.ldap_bind_format,
            settings.ldap_use_tls,
            settings.ldap_ca_file,
        )

    def bind_user(self, username: str) -> str:
        """The bind name for an already normalized username."""
        return self.bind_format.format(username=username)

    def server(self) -> Server:
        tls = None
        if self.use_tls:
            tls = Tls(
                validate=ssl.CERT_REQUIRED,
                ca_certs_file=str(self.ca_file) if self.ca_file else None,
                sni=self.host,
            )
        return Server(
            self.host,
            port=self.port,
            use_ssl=self.use_tls,
            tls=tls,
            connect_timeout=self.connect_timeout,
            get_info=NONE,
        )


def whoami_names(authzid: object, username: str, bind_user: str) -> bool:
    """Whether a WhoAmI answer names the typed username.

    ``u:DOMAIN\\name`` passes when ``name`` equals ``username`` case-insensitively
    (the domain part is not checked; multi-domain forests are not handled).
    ``dn:...`` passes when it equals ``bind_user`` case-insensitively. Anything else,
    including an empty (anonymous) answer, is refused.
    """
    if not isinstance(authzid, str) or not username:
        return False
    if authzid.startswith("u:"):
        value = authzid[2:]
        if value.count("\\") != 1:
            return False
        domain, _, name = value.partition("\\")
        return bool(domain) and name.casefold() == username.casefold()
    if authzid.startswith("dn:"):
        return bool(authzid[3:]) and authzid[3:].casefold() == bind_user.casefold()
    return False


def check_password(config: LDAPBindConfig, username: str, password: str) -> None:
    """Bind as ``username`` with ``password`` and require WhoAmI to name that account.

    ``username`` must already be normalized (``keep.identity.adapi.normalize_username``).
    Returns None on success; raises SignInRejected or SignInUnavailable. An empty
    password is refused before any connection is made, because an empty-password
    simple bind succeeds anonymously on AD. Blocking: run it in a thread pool.
    """
    if not isinstance(password, str) or not password:
        raise SignInRejected(REJECT_EMPTY_PASSWORD)
    _hide_credentials()
    bind_user = config.bind_user(username)
    try:
        connection = Connection(
            config.server(),
            user=bind_user,
            password=password.encode("utf-8"),
            authentication=SIMPLE,
            client_strategy=SYNC,
            read_only=True,
            receive_timeout=config.receive_timeout,
            raise_exceptions=True,
            auto_referrals=False,
        )
    except LDAPException:
        raise SignInUnavailable(UNAVAILABLE_CONFIGURATION) from None
    try:
        try:
            if not connection.bind():
                # A result ldap3 doesn't raise for (a referral, for example).
                raise SignInUnavailable(UNAVAILABLE_LDAP_RESULT)
            authzid = connection.extend.standard.who_am_i()
        except LDAPOperationResult as exc:
            if getattr(exc, "result", None) in _REJECTING_RESULTS:
                raise SignInRejected(REJECT_CREDENTIALS) from None
            raise SignInUnavailable(UNAVAILABLE_LDAP_RESULT) from None
        except LDAPException:
            raise SignInUnavailable(UNAVAILABLE_LDAP) from None
        except OSError:
            raise SignInUnavailable(UNAVAILABLE_LDAP) from None
    finally:
        try:
            connection.unbind()
        except (LDAPException, OSError):
            pass
        # Drop the only reference to the encoded password.
        connection.password = None
    if not whoami_names(authzid, username, bind_user):
        raise SignInRejected(REJECT_IDENTITY_MISMATCH)
