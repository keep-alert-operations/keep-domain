"""Read-only ADAPI (the company AD REST API) client and directory reader.

Requirements: REV-73; identity configuration 6-7; worker scope 4.

Identity is the lowercase sAMAccountName under the source ``adapi``. Every HTTP
call has an explicit timeout derived from the caller's cap and, inside a request
or a background job, from ``keep.request_budget``. Errors carry fixed reason
codes only: never response text, URLs (which hold names) or the ClientId.

Query arrays (``attributesToLoad``) are sent as repeated parameters
(``attributesToLoad=a&attributesToLoad=b``), the form ASP.NET array binding
accepts by default; the local mock accepts repeated and comma-separated values.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Iterator, Literal, Mapping, Sequence
from urllib.parse import urlsplit

import httpx

from keep import request_budget
from keep.shared.errors import AppError

from .directory import (
    DirectoryEvidence,
    DirectoryObject,
    DirectoryUnavailable,
    DirectoryVerifier,
    PrincipalKey,
    failure_reason,
)

Kind = Literal["user", "team"]
Params = Sequence[tuple[str, str]]

SOURCE = "adapi"
# Per-call caps: inside a request, in the refresh command (no budget), and in a
# background save (its own budget). The effective timeout is call_timeout(cap).
REQUEST_CALL_CAP = 3.0
REFRESH_CALL_CAP = 5.0
JOB_CALL_CAP = 5.0
# Verifier deadlines: an inline save on pick and the refresh; a background save
# uses job_verification_deadline().
INLINE_VERIFY_DEADLINE = 7.0
REFRESH_VERIFY_DEADLINE = 60.0
MAX_OBJECTS = 10000
USER_ATTRIBUTES = ("sAMAccountName", "displayName", "userAccountControl")
GROUP_ATTRIBUTES = ("sAMAccountName", "displayName", "cn")
# Identity configuration 2: AD-forbidden characters, plus "@" (it would select a
# userPrincipalName). Control characters are refused separately.
FORBIDDEN_CHARACTERS = frozenset('"/\\[]:;|=,+*?<>@')


class InvalidUsername(ValueError):
    """The value cannot be an AD sAMAccountName Keep accepts."""


def normalize_username(value: str) -> str:
    """Trim, require 1-64 characters without forbidden ones, return lowercase.

    Shared by sign-in and save on pick so both address the same principal.
    """
    if not isinstance(value, str):
        raise InvalidUsername("username must be text")
    name = value.strip()
    if not 1 <= len(name) <= 64:
        raise InvalidUsername("username length is invalid")
    if any(ch in FORBIDDEN_CHARACTERS or ord(ch) < 32 or 127 <= ord(ch) < 160 for ch in name):
        raise InvalidUsername("username contains a forbidden character")
    return name.lower()


def principal_key(username: str, source: str = SOURCE) -> PrincipalKey:
    """The principal key of a username (normalized; raises InvalidUsername)."""
    return PrincipalKey(source, normalize_username(username))


def escape_filter_value(value: str) -> str:
    """Escape an LDAP filter assertion value per RFC 4515 section 3."""
    return (
        value.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


def budget_seconds(cap: float, reserve: float) -> float:
    """``min(cap, request_budget.remaining() - reserve)``; ``cap`` without a budget.

    Raises DirectoryUnavailable("directory_deadline") when nothing usable is left.
    """
    try:
        left = request_budget.remaining()
    except AppError:
        raise DirectoryUnavailable("directory_deadline") from None
    value = cap if left is None else min(cap, left - reserve)
    if value <= 0:
        raise DirectoryUnavailable("directory_deadline")
    return value


def call_timeout(cap: float) -> float:
    """Per-call timeout ``min(cap, remaining - 1 s)``, or ``cap`` without a budget."""
    return budget_seconds(cap, 1.0)


def job_verification_deadline() -> float:
    """Verifier deadline inside a background save: ``min(60 s, remaining - 15 s)``."""
    return budget_seconds(REFRESH_VERIFY_DEADLINE, 15.0)


@dataclass(frozen=True)
class ADAPIConfig:
    base_url: str
    client_id: str = field(repr=False)
    lookup_batch: int = 50
    source: str = SOURCE

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("ADAPI requires an explicit origin without embedded secrets")
        if not self.client_id:
            raise ValueError("ADAPI ClientId is required")
        if not 1 <= self.lookup_batch <= 200 or not self.source:
            raise ValueError("invalid ADAPI lookup allocation")

    @classmethod
    def from_settings(cls, settings: Any) -> ADAPIConfig:
        """From ``KEEP_ADAPI_URL``, ``KEEP_ADAPI_CLIENT_ID``, ``KEEP_ADAPI_LOOKUP_BATCH``."""
        if not settings.adapi_url or settings.adapi_client_id is None:
            raise ValueError("ADAPI URL and ClientId are required")
        return cls(
            settings.adapi_url,
            settings.adapi_client_id.get_secret_value(),
            settings.adapi_lookup_batch,
        )


class ADAPIClient:
    """Synchronous ADAPI client; one per verification (not shared across threads).

    ``call_cap`` bounds each call (the effective timeout is ``call_timeout(cap)``,
    or a smaller per-call ``timeout``). ``stop`` is checked before every call.
    ``calls`` counts the requests sent.
    """

    def __init__(
        self,
        config: ADAPIConfig,
        *,
        call_cap: float,
        stop: threading.Event | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        if not 0 < call_cap <= 10:
            raise ValueError("invalid ADAPI call timeout cap")
        self.config, self.call_cap, self.stop = config, call_cap, stop
        self.calls = 0
        self._http = httpx.Client(
            base_url=config.base_url.rstrip("/"),
            headers={"ClientId": config.client_id, "Accept": "application/json"},
            transport=transport,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ADAPIClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _get(self, path: str, params: Params, timeout: float | None) -> list[dict]:
        if self.stop is not None and self.stop.is_set():
            raise DirectoryUnavailable("directory_stopped")
        cap = self.call_cap if timeout is None else min(timeout, self.call_cap)
        seconds = call_timeout(cap)
        self.calls += 1
        try:
            response = self._http.get(path, params=list(params), timeout=httpx.Timeout(seconds))
        except httpx.TimeoutException:
            raise DirectoryUnavailable("directory_timeout") from None
        except httpx.HTTPError:
            raise DirectoryUnavailable("directory_transport_failure") from None
        if response.status_code != 200:
            raise DirectoryUnavailable("directory_status_rejected")
        try:
            body = response.json()
        except ValueError:
            raise DirectoryUnavailable("directory_response_invalid") from None
        if not isinstance(body, list) or not all(isinstance(row, dict) for row in body):
            raise DirectoryUnavailable("directory_response_invalid")
        return body

    def find_users(self, params: Params, *, timeout: float | None = None) -> list[dict]:
        """``GET /users`` with OR'ed ADAPI params (exact unless ``*`` is used)."""
        return self._get("/users", params, timeout)

    def find_groups(self, params: Params, *, timeout: float | None = None) -> list[dict]:
        """``GET /groups`` with OR'ed ADAPI params (exact unless ``*`` is used)."""
        return self._get("/groups", params, timeout)

    def group_members(self, sam: str, *, timeout: float | None = None) -> list[dict]:
        """Recursive user members of a group (cycle-safe, no cap, no attributesToLoad)."""
        return self._get(
            "/groups/members/user",
            [("samAccountName", sam), ("isRecursive", "true")],
            timeout,
        )

    def lookup_user_rows(self, username: str, *, timeout: float | None = None) -> list[dict]:
        """Raw ``/users`` rows for an exact sAMAccountName: zero, one or more.

        For sign-in, which tells the three apart. Every row must name the requested
        account (case-insensitively), otherwise this raises DirectoryUnavailable.
        """
        name = normalize_username(username)
        rows = self.find_users(exact_params(name, USER_ATTRIBUTES), timeout=timeout)
        for row in rows:
            if _sam(row) != name:
                raise DirectoryUnavailable("directory_identity_mismatch")
        return rows


def attribute_params(attributes: Iterable[str]) -> list[tuple[str, str]]:
    return [("attributesToLoad", name) for name in attributes]


def exact_params(sam: str, attributes: Iterable[str]) -> list[tuple[str, str]]:
    return [("samAccountName", sam), *attribute_params(attributes)]


def batch_filter(names: Iterable[str]) -> str:
    """``(|(sAMAccountName=a)(sAMAccountName=b)...)`` with RFC 4515 escaping."""
    return "(|" + "".join(f"(sAMAccountName={escape_filter_value(n)})" for n in names) + ")"


def _text(row: Mapping, name: str) -> str | None:
    value = row.get(name)
    if value is None:
        lowered = {k.casefold(): v for k, v in row.items() if isinstance(k, str)}
        value = lowered.get(name.casefold())
    return value.strip() if isinstance(value, str) and value.strip() else None


def _sam(row: Mapping) -> str:
    value = _text(row, "sAMAccountName")
    if value is None:
        raise DirectoryUnavailable("directory_response_invalid")
    return value.lower()


def _uac(row: Mapping) -> int:
    value = _text(row, "userAccountControl")
    if value is None and isinstance(row.get("userAccountControl"), int):
        value = row["userAccountControl"]
    try:
        if value is None or isinstance(value, bool):
            raise ValueError()
        return int(value)
    except (TypeError, ValueError):
        raise DirectoryUnavailable("directory_response_invalid") from None


def user_object(source: str, row: Mapping) -> DirectoryObject:
    """A verified user from one ``/users`` row: eligible unless UAC bit 2 is set.

    The label is ``displayName``, falling back to the sAMAccountName.
    """
    sam = _sam(row)
    return DirectoryObject(
        PrincipalKey(source, sam), "user", _text(row, "displayName") or sam, _uac(row) & 2 == 0
    )


def group_object(source: str, row: Mapping) -> DirectoryObject:
    """A verified group (eligible); label ``displayName`` if returned, else ``cn``."""
    sam = _sam(row)
    label = _text(row, "displayName") or _text(row, "cn") or sam
    return DirectoryObject(PrincipalKey(source, sam), "team", label, True)


def _member_name(row: Mapping) -> str | None:
    """A member's key, or None for accounts Keep never admits.

    Computer accounts (``$``) are skipped; so is a name sign-in would refuse, which
    can never be a Keep principal and must not fail the whole group.
    """
    sam = _sam(row)
    if sam.endswith("$"):
        return None
    try:
        return sam if normalize_username(sam) == sam else None
    except InvalidUsername:
        return None


class ADAPIDirectoryReader:
    """``DirectoryReader`` over ADAPI with kind hints and batched member names.

    Not thread-safe. Create one per evidence, so cached rows never outlive the
    generation that was allocated before reading them.
    """

    def __init__(
        self,
        client: ADAPIClient,
        *,
        hints: Mapping[PrincipalKey, Kind] | None = None,
        max_objects: int = MAX_OBJECTS,
    ):
        self.client, self.max_objects = client, max_objects
        self.source = client.config.source
        self.batch = client.config.lookup_batch
        self.hints: dict[PrincipalKey, Kind] = {}
        for key, kind in (hints or {}).items():
            self.hint(key, kind)
        self.objects: dict[PrincipalKey, DirectoryObject] = {}

    def hint(self, key: PrincipalKey, kind: Kind) -> None:
        """Ask the ``kind`` endpoint first for ``key`` (default: users first)."""
        if kind not in ("user", "team"):
            raise ValueError("invalid directory kind hint")
        self.hints[key] = kind

    def _name(self, key: PrincipalKey) -> str:
        if key.source != self.source:
            raise DirectoryUnavailable("directory_source_mismatch")
        try:
            name = normalize_username(key.object_id)
        except InvalidUsername:
            raise DirectoryUnavailable("directory_identity_invalid") from None
        if name != key.object_id:
            raise DirectoryUnavailable("directory_identity_invalid")
        return name

    def _exact(self, kind: Kind, name: str) -> DirectoryObject | None:
        if kind == "user":
            rows = self.client.find_users(exact_params(name, USER_ATTRIBUTES))
        else:
            rows = self.client.find_groups(exact_params(name, GROUP_ATTRIBUTES))
        if len(rows) > 1:
            raise DirectoryUnavailable("directory_ambiguous")
        if not rows:
            return None
        if _sam(rows[0]) != name:
            raise DirectoryUnavailable("directory_identity_mismatch")
        return (user_object if kind == "user" else group_object)(self.source, rows[0])

    def lookup(self, key: PrincipalKey) -> DirectoryObject:
        """Cached, else the hinted endpoint then the other; deleted only if both are empty."""
        cached = self.objects.get(key)
        if cached is not None:
            return cached
        name = self._name(key)
        first: Kind = self.hints.get(key, "user")
        second: Kind = "team" if first == "user" else "user"
        obj = self._exact(first, name) or self._exact(second, name)
        if obj is None:
            # Both endpoints answered 200 with zero rows: the account is gone.
            # publish() keeps a tombstone's previously stored kind.
            obj = DirectoryObject(key, first, name, False, deleted=True)
        self.objects[key] = obj
        return obj

    def _batch(self, names: Sequence[str]) -> dict[str, dict]:
        rows = self.client.find_users(
            [("customFilter", batch_filter(names)), *attribute_params(USER_ATTRIBUTES)]
        )
        wanted, found = set(names), {}
        for row in rows:
            sam = _sam(row)
            if sam not in wanted:
                continue
            if sam in found:
                raise DirectoryUnavailable("directory_ambiguous")
            found[sam] = row
        return found

    def prefetch_users(self, keys: Iterable[PrincipalKey]) -> None:
        """Cache user roots, ``lookup_batch`` names per ``/users`` call.

        A name a batch omits is not cached, so ``lookup()`` asks both exact
        endpoints for it: only that can prove deletion.
        """
        names = sorted({self._name(k) for k in keys if k not in self.objects})
        for start in range(0, len(names), self.batch):
            for row in self._batch(names[start : start + self.batch]).values():
                obj = user_object(self.source, row)
                self.objects[obj.key] = obj

    def members(self, group: PrincipalKey) -> Iterator[PrincipalKey]:
        """Recursive user members, flattened to direct group -> user edges.

        Display names come from batched ``/users`` calls, yielded batch by batch so
        the verifier's deadline is checked between calls. A member a batch omits
        keeps the members route's own userAccountControl with its sAMAccountName
        as label; it is never marked deleted from a batch.
        """
        status: dict[str, int] = {}
        for row in self.client.group_members(self._name(group)):
            sam = _member_name(row)
            if sam is not None:
                status[sam] = _uac(row)
        if len(status) + 1 > self.max_objects:
            # Fail before any name batch: the group cannot fit one evidence.
            raise DirectoryUnavailable("directory_allocation_exceeded")
        names = sorted(status)
        for start in range(0, len(names), self.batch):
            chunk = names[start : start + self.batch]
            pending = [n for n in chunk if PrincipalKey(self.source, n) not in self.objects]
            found = self._batch(pending) if pending else {}
            for sam in chunk:
                key = PrincipalKey(self.source, sam)
                if key not in self.objects:
                    row = found.get(sam)
                    self.objects[key] = (
                        user_object(self.source, row)
                        if row is not None
                        else DirectoryObject(key, "user", sam, status[sam] & 2 == 0)
                    )
                yield key


def verify_roots(
    config: ADAPIConfig,
    roots: Mapping[PrincipalKey, Kind],
    generation: int,
    *,
    deadline_seconds: float,
    call_cap: float,
    max_objects: int = MAX_OBJECTS,
    stop: threading.Event | None = None,
    transport: httpx.BaseTransport | None = None,
) -> DirectoryEvidence:
    """Read ``roots`` (key -> kind hint) into one evidence; never raises for ADAPI.

    Allocate ``generation`` before calling, and hold no database connection while
    this reads. More than one user root is prefetched in batches. A failure comes
    back as incomplete evidence with ``failure_reason`` set.
    """
    started = datetime.now(UTC)
    try:
        with ADAPIClient(config, call_cap=call_cap, stop=stop, transport=transport) as client:
            reader = ADAPIDirectoryReader(client, hints=roots, max_objects=max_objects)
            users = [key for key, kind in roots.items() if kind == "user"]
            if len(users) > 1:
                reader.prefetch_users(users)
            return DirectoryVerifier(
                reader, max_objects=max_objects, deadline_seconds=deadline_seconds
            ).verify(roots, generation)
    except DirectoryUnavailable as exc:
        return DirectoryEvidence.failed(
            config.source, generation, roots, started, failure_reason(exc)
        )


def verify_root(
    config: ADAPIConfig,
    username: str,
    kind: Kind,
    generation: int,
    *,
    deadline_seconds: float,
    call_cap: float,
    max_objects: int = MAX_OBJECTS,
    stop: threading.Event | None = None,
    transport: httpx.BaseTransport | None = None,
) -> DirectoryEvidence:
    """One root (a person, or a group with its recursive members) for save on pick.

    ``username`` is normalized (InvalidUsername for a refused name). Use
    ``INLINE_VERIFY_DEADLINE``/``REQUEST_CALL_CAP`` inline, and
    ``job_verification_deadline()``/``JOB_CALL_CAP`` in a background save.
    """
    if kind not in ("user", "team"):
        raise ValueError("invalid directory kind")
    return verify_roots(
        config,
        {principal_key(username, config.source): kind},
        generation,
        deadline_seconds=deadline_seconds,
        call_cap=call_cap,
        max_objects=max_objects,
        stop=stop,
        transport=transport,
    )


def user_evidence(
    source: str, row: Mapping, generation: int, started_at: datetime
) -> DirectoryEvidence:
    """Complete single-person evidence from the one ``/users`` row sign-in read.

    Allocate ``generation`` before reading the row. The person is the only root.
    """
    obj = user_object(source, row)
    key = obj.key
    eligible = obj.eligible and not obj.deleted
    return DirectoryEvidence(
        source,
        generation,
        started_at,
        datetime.now(UTC),
        frozenset({key}),
        {key: obj},
        {},
        {key: frozenset({key}) if eligible else frozenset()},
        True,
        negative_keys=frozenset() if eligible else frozenset({key}),
    )
