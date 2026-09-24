"""Bounded, read-only ldap3 adapter with deployment-supplied schema semantics."""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

from ldap3 import BASE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from .directory import DirectoryObject, DirectoryUnavailable, PrincipalKey


@dataclass(frozen=True)
class LDAPSchema:
    base_dn: str
    user_filter: str
    team_filter: str
    id_attribute: str
    label_attribute: str
    member_attribute: str
    eligibility_attribute: str
    # Explicit deployment choice, e.g. entryUUID text or AD objectGUID bytes_le.
    id_encoding: Literal["text", "uuid", "guid_le"]
    eligibility_values: tuple[str, ...] = ()
    disabled_bitmask: int | None = None
    # Attribute mode includes users whose primary-user attribute equals the
    # team's primary-team attribute. It supports explicitly mapped RID schemas.
    primary_group_mode: Literal["none", "attribute"] = "none"
    primary_user_attribute: str | None = None
    primary_team_attribute: str | None = None
    schema_qualified: bool = False

    def __post_init__(self) -> None:
        attrs = [
            self.id_attribute,
            self.label_attribute,
            self.member_attribute,
            self.eligibility_attribute,
            self.primary_user_attribute,
            self.primary_team_attribute,
        ]
        if any(a is not None and not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", a) for a in attrs):
            raise ValueError("invalid LDAP attribute configuration")
        if (
            not self.base_dn
            or not self.user_filter.startswith("(")
            or not self.team_filter.startswith("(")
        ):
            raise ValueError("explicit LDAP base and filters required")
        if bool(self.eligibility_values) == (self.disabled_bitmask is not None):
            raise ValueError("configure exactly one LDAP eligibility mapping")
        if self.disabled_bitmask is not None and self.disabled_bitmask < 1:
            raise ValueError("invalid disabled bitmask")
        if self.primary_group_mode == "attribute" and not all(
            (self.primary_user_attribute, self.primary_team_attribute)
        ):
            raise ValueError("primary-group attribute mapping required")
        if self.primary_group_mode not in ("none", "attribute") or self.id_encoding not in (
            "text",
            "uuid",
            "guid_le",
        ):
            raise ValueError("unsupported LDAP mapping")


@dataclass(frozen=True)
class LDAPConfig:
    source: str
    hostname: str
    bind_dn: str
    password: str = field(repr=False)
    ca_file: str
    schema: LDAPSchema
    port: int = 636
    connect_timeout: int = 3
    receive_timeout: int = 5
    page_size: int = 200
    max_pages: int = 100
    max_objects: int = 10000

    def __post_init__(self) -> None:
        if not all((self.source, self.hostname, self.bind_dn, self.password, self.ca_file)):
            raise ValueError("LDAP credentials, source, host and trust bundle are required")
        if (
            not 1 <= self.port <= 65535
            or not 0 < self.connect_timeout <= 10
            or not 0 < self.receive_timeout <= 10
        ):
            raise ValueError("invalid LDAP network bounds")
        if not 1 <= self.page_size <= 200 or self.max_pages < 1 or self.max_objects < 1:
            raise ValueError("invalid LDAP allocation")


class LDAPDirectoryReader:
    """One connection per verification; no shared mutable ldap3 connection.

    No referral following, plaintext fallback, user-password authentication or
    memberOf assumption. Ranged attributes fail closed until deployment supplies
    an explicitly supported mapping; this cannot silently truncate a large team.
    """

    def __init__(self, config: LDAPConfig, *, connection: Any = None):
        self.config, self.source, self.schema = config, config.source, config.schema
        self.connection = connection
        self._owned = connection is None
        self._entries: dict[PrincipalKey, dict] = {}

    def __enter__(self) -> LDAPDirectoryReader:
        if self.connection is None:
            try:
                tls = Tls(
                    validate=ssl.CERT_REQUIRED,
                    ca_certs_file=self.config.ca_file,
                    valid_names=[self.config.hostname],
                    version=ssl.PROTOCOL_TLS_CLIENT,
                )
                server = Server(
                    self.config.hostname,
                    port=self.config.port,
                    use_ssl=True,
                    tls=tls,
                    connect_timeout=self.config.connect_timeout,
                    get_info=None,
                )
                self.connection = Connection(
                    server,
                    user=self.config.bind_dn,
                    password=self.config.password,
                    read_only=True,
                    auto_referrals=False,
                    receive_timeout=self.config.receive_timeout,
                    raise_exceptions=True,
                )
                if not self.connection.bind():
                    raise DirectoryUnavailable("directory_bind_failed")
            except (LDAPException, OSError):
                raise DirectoryUnavailable("directory_transport_failure") from None
        return self

    def __exit__(self, *args: Any) -> None:
        if self._owned and self.connection is not None:
            self.connection.unbind()
            self.connection = None

    def _search(self, base: str, query: str, *, scope: Any = SUBTREE) -> list[dict]:
        if self.connection is None:
            raise DirectoryUnavailable("directory_connection_required")
        attributes = list(
            dict.fromkeys(
                a
                for a in (
                    self.schema.id_attribute,
                    self.schema.label_attribute,
                    self.schema.member_attribute,
                    self.schema.eligibility_attribute,
                    self.schema.primary_team_attribute,
                )
                if a
            )
        )
        entries: list[dict] = []
        cookie: bytes | None = None
        cookies: set[bytes] = set()
        try:
            for _ in range(self.config.max_pages):
                self.connection.search(
                    base,
                    query,
                    search_scope=scope,
                    attributes=attributes,
                    time_limit=self.config.receive_timeout,
                    paged_size=self.config.page_size,
                    paged_criticality=True,
                    paged_cookie=cookie,
                )
                if self.connection.result.get("result") != 0:
                    raise DirectoryUnavailable("directory_search_incomplete")
                for entry in self.connection.response:
                    if entry.get("type") != "searchResEntry":
                        raise DirectoryUnavailable("directory_referral_or_partial_result")
                    if any(";range=" in k.casefold() for k in entry.get("raw_attributes", {})):
                        raise DirectoryUnavailable("directory_ranged_membership_unqualified")
                    entries.append(entry)
                    if len(entries) > self.config.max_objects:
                        raise DirectoryUnavailable("directory_allocation_exceeded")
                control = self.connection.result.get("controls", {}).get("1.2.840.113556.1.4.319")
                if control is None:
                    raise DirectoryUnavailable("directory_page_control_missing")
                cookie = control.get("value", {}).get("cookie")
                if cookie is None:
                    raise DirectoryUnavailable("directory_page_cookie_missing")
                if not cookie:
                    return entries
                if cookie in cookies:
                    raise DirectoryUnavailable("directory_page_loop")
                cookies.add(cookie)
        except (LDAPException, OSError):
            raise DirectoryUnavailable("directory_transport_failure") from None
        raise DirectoryUnavailable("directory_page_allocation_exceeded")

    @staticmethod
    def _values(entry: dict, attribute: str) -> list[bytes]:
        attrs = {k.casefold(): v for k, v in entry.get("raw_attributes", {}).items()}
        return attrs.get(attribute.casefold(), [])

    def _one(self, entry: dict, attribute: str) -> bytes:
        values = self._values(entry, attribute)
        if len(values) != 1:
            raise DirectoryUnavailable("directory_attribute_mapping_incomplete")
        return values[0]

    def _key(self, entry: dict) -> PrincipalKey:
        value = self._one(entry, self.schema.id_attribute)
        try:
            if self.schema.id_encoding == "guid_le":
                object_id = str(UUID(bytes_le=value))
            elif self.schema.id_encoding == "uuid":
                object_id = str(UUID(value.decode("utf-8")))
            else:
                object_id = value.decode("utf-8")
            return PrincipalKey(self.source, object_id)
        except (UnicodeError, ValueError):
            raise DirectoryUnavailable("directory_identity_mapping_invalid") from None

    def _identity_filter(self, key: PrincipalKey) -> str:
        if key.source != self.source:
            raise DirectoryUnavailable("directory_source_mismatch")
        try:
            value = (
                "".join(f"\\{b:02x}" for b in UUID(key.object_id).bytes_le)
                if self.schema.id_encoding == "guid_le"
                else escape_filter_chars(key.object_id)
            )
        except ValueError:
            raise DirectoryUnavailable("directory_identity_mapping_invalid") from None
        return f"({self.schema.id_attribute}={value})"

    def lookup(self, key: PrincipalKey) -> DirectoryObject:
        identity = self._identity_filter(key)
        # Separate schema filters establish type without guessing objectClass.
        users = self._search(self.schema.base_dn, f"(&{identity}{self.schema.user_filter})")
        teams = self._search(self.schema.base_dn, f"(&{identity}{self.schema.team_filter})")
        if len(users) + len(teams) > 1:
            raise DirectoryUnavailable("directory_identity_ambiguous")
        if not users and not teams:
            return DirectoryObject(key, "user", key.object_id, False, deleted=True)
        entry = (users or teams)[0]
        if self._key(entry) != key:
            raise DirectoryUnavailable("directory_identity_binding_conflict")
        self._entries[key] = entry
        try:
            label = self._one(entry, self.schema.label_attribute).decode("utf-8")
            eligible = True
            if users:
                status = self._one(entry, self.schema.eligibility_attribute).decode("utf-8")
                eligible = (
                    not (int(status) & self.schema.disabled_bitmask)
                    if self.schema.disabled_bitmask is not None
                    else status in self.schema.eligibility_values
                )
        except (UnicodeError, ValueError):
            raise DirectoryUnavailable("directory_eligibility_mapping_invalid") from None
        return DirectoryObject(key, "user" if users else "team", label, eligible)

    def members(self, group: PrincipalKey):
        entry = self._entries.get(group)
        if entry is None:
            raise DirectoryUnavailable("directory_group_not_verified")
        for dn in self._values(entry, self.schema.member_attribute):
            try:
                base = dn.decode("utf-8")
            except UnicodeError:
                raise DirectoryUnavailable("directory_member_mapping_invalid") from None
            rows = self._search(
                base, f"(|{self.schema.user_filter}{self.schema.team_filter})", scope=BASE
            )
            if len(rows) != 1:
                raise DirectoryUnavailable("directory_member_unresolved")
            yield self._key(rows[0])
        if self.schema.primary_group_mode == "attribute":
            try:
                primary = self._one(entry, self.schema.primary_team_attribute).decode("utf-8")
            except UnicodeError:
                raise DirectoryUnavailable("directory_primary_group_mapping_invalid") from None
            query = f"(&{self.schema.user_filter}({self.schema.primary_user_attribute}={escape_filter_chars(primary)}))"
            for user in self._search(self.schema.base_dn, query):
                yield self._key(user)

    def search(self, term: str, limit: int = 50) -> tuple[DirectoryObject, ...]:
        if not 2 <= len(term) <= 100 or not 1 <= limit <= 200:
            raise ValueError("invalid directory search bounds")
        query = f"(&(|{self.schema.user_filter}{self.schema.team_filter})({self.schema.label_attribute}=*{escape_filter_chars(term)}*))"
        rows = self._search(self.schema.base_dn, query)
        keys = sorted({self._key(row) for row in rows})[:limit]
        return tuple(self.lookup(key) for key in keys)
