"""Bounded, read-only directory for a development-only local Keycloak realm.

Native Keycloak UUIDs are identities; usernames and group paths are display data.
This adapter deliberately does not change the production LDAP reader.
"""

from __future__ import annotations

import json
import os
import ssl
import time
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .directory import DirectoryObject, DirectoryUnavailable, PrincipalKey


class LocalKeycloakConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    issuer: str
    source: Literal["keycloak-local"]
    client_id: Literal["keep-directory"]
    client_secret_env: Literal["KEEP_LOCAL_DIRECTORY_SECRET"]
    ca_file: str
    superadmin_group: str
    max_objects: int = Field(ge=1, le=10000)
    page_size: int = Field(ge=1, le=200)
    max_pages: int = Field(ge=1, le=100000)
    local_only: Literal[True]

    @model_validator(mode="after")
    def local_binding(self):
        parsed = urlsplit(self.issuer)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path != "/realms/keep-local"
            or not self.ca_file
        ):
            raise ValueError("local Keycloak requires a trusted loopback HTTPS keep-local realm")
        if str(UUID(self.superadmin_group)) != self.superadmin_group:
            raise ValueError("superadmin_group requires a canonical native Keycloak UUID")
        return self


def require_development() -> None:
    if os.environ.get("KEEP_ENVIRONMENT") != "development":
        raise ValueError(
            "local Keycloak directory requires explicit KEEP_ENVIRONMENT=development"
        )


def load_config(path: Path) -> LocalKeycloakConfig:
    require_development()
    if path.stat().st_size > 65536:
        raise ValueError("local directory configuration exceeds its size limit")
    config = LocalKeycloakConfig.model_validate_json(path.read_bytes())
    if not os.environ.get(config.client_secret_env):
        raise ValueError("local directory service-account secret binding is missing")
    return config


class KeycloakDirectoryReader:
    def __init__(self, config: LocalKeycloakConfig, *, transport=None):
        require_development()
        secret = os.environ.get(config.client_secret_env)
        if not secret:
            raise ValueError("local directory service-account secret binding is missing")
        self.config, self.source = config, config.source
        self.client = httpx.Client(
            verify=ssl.create_default_context(cafile=config.ca_file),
            transport=transport,
            timeout=5,
            follow_redirects=False,
            trust_env=False,
        )
        parsed = urlsplit(config.issuer)
        self.admin = f"{parsed.scheme}://{parsed.netloc}/admin/realms/keep-local"
        self.objects: dict[PrincipalKey, DirectoryObject] = {}
        self.edges: dict[PrincipalKey, frozenset[PrincipalKey]] = {}
        self.service_accounts: set[PrincipalKey] = set()
        self.pages = 0
        self.deadline = time.monotonic() + 55
        try:
            token = self._request(
                "POST",
                config.issuer + "/protocol/openid-connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": config.client_id,
                    "client_secret": secret,
                },
            )
            if not isinstance(token, dict) or not isinstance(token.get("access_token"), str):
                raise DirectoryUnavailable("local_directory_token_invalid")
            self.client.headers["Authorization"] = "Bearer " + token["access_token"]
        except BaseException:
            self.client.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.client.close()

    def _request(self, method, url, *, missing=False, **kwargs):
        if time.monotonic() >= self.deadline:
            raise DirectoryUnavailable("local_directory_deadline")
        try:
            with self.client.stream(method, url, **kwargs) as response:
                if missing and response.status_code == 404:
                    return None
                if response.status_code != 200:
                    raise DirectoryUnavailable("local_directory_request_failed")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 2 * 1024 * 1024 or time.monotonic() >= self.deadline:
                        raise DirectoryUnavailable("local_directory_response_limit")
                return json.loads(body)
        except (httpx.HTTPError, ValueError) as exc:
            raise DirectoryUnavailable("local_directory_request_failed") from exc

    @staticmethod
    def _id(row):
        try:
            value = row["id"]
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise ValueError
            return value
        except (KeyError, TypeError, ValueError) as exc:
            raise DirectoryUnavailable("local_directory_invalid_identity") from exc

    def _page(self, path, **params):
        seen = set()
        offset = 0
        while True:
            self.pages += 1
            if self.pages > self.config.max_pages:
                raise DirectoryUnavailable("local_directory_page_limit")
            rows = self._request(
                "GET",
                self.admin + path,
                params={**params, "first": offset, "max": self.config.page_size},
            )
            if not isinstance(rows, list) or len(rows) > self.config.page_size:
                raise DirectoryUnavailable("local_directory_invalid_page")
            for row in rows:
                identity = self._id(row)
                if identity in seen:
                    raise DirectoryUnavailable("local_directory_repeated_page")
                seen.add(identity)
                if len(seen) > self.config.max_objects:
                    raise DirectoryUnavailable("local_directory_object_limit")
                yield row
            if len(rows) < self.config.page_size:
                return
            offset += len(rows)

    def _object(self, row, kind):
        key = PrincipalKey(self.source, self._id(row))
        if kind == "user":
            if not isinstance(row.get("enabled"), bool):
                raise DirectoryUnavailable("local_directory_missing_eligibility")
            if row.get("serviceAccountClientId"):
                self.service_accounts.add(key)
                return None
            label = " ".join(
                part
                for part in (row.get("firstName", ""), row.get("lastName", ""))
                if isinstance(part, str) and part
            ) or row.get("username")
            eligible = row["enabled"]
        else:
            label, eligible = row.get("name"), True
        if not isinstance(label, str) or not label or len(label) > 1024:
            raise DirectoryUnavailable("local_directory_invalid_label")
        obj = DirectoryObject(key, kind, label, eligible)
        if key in self.objects and self.objects[key] != obj:
            # A same-user disablement is a positively observed negative even
            # when a concurrent edit makes the overall traversal incomplete.
            if kind == "user" and self.objects[key].kind == "user" and not eligible:
                self.objects[key] = obj
            raise DirectoryUnavailable("local_directory_ambiguous_identity")
        self.objects[key] = obj
        if len(self.objects) + len(self.service_accounts) > self.config.max_objects:
            raise DirectoryUnavailable("local_directory_object_limit")
        return key

    def load(self):
        """Enumerate the small local realm completely before any publication."""
        for row in self._page("/users", briefRepresentation="false"):
            self._object(row, "user")
        pending = list(self._page("/groups", populateHierarchy="false"))
        seen = set()
        while pending:
            row = pending.pop()
            group = self._object(row, "team")
            if group in seen:
                raise DirectoryUnavailable("local_directory_ambiguous_hierarchy")
            seen.add(group)
            children = list(self._page(f"/groups/{group.object_id}/children"))
            members = set()
            for member in self._page(
                f"/groups/{group.object_id}/members", briefRepresentation="false"
            ):
                key = PrincipalKey(self.source, self._id(member))
                if key in self.service_accounts:
                    continue
                if key not in self.objects or self.objects[key].kind != "user":
                    raise DirectoryUnavailable("local_directory_changed_during_read")
                if self._object(member, "user") != key:
                    raise DirectoryUnavailable("local_directory_changed_during_read")
                members.add(key)
            members.update(PrincipalKey(self.source, self._id(child)) for child in children)
            self.edges[group] = frozenset(members)
            pending.extend(children)
        return frozenset(self.objects)

    def lookup(self, key: PrincipalKey) -> DirectoryObject:
        if key.source != self.source:
            raise DirectoryUnavailable("local_directory_source_mismatch")
        if key in self.objects:
            return self.objects[key]
        # A prior identity missing from enumeration needs explicit two-kind 404
        # confirmation. Missing pages may never fabricate account deletion.
        try:
            if str(UUID(key.object_id)) != key.object_id:
                raise ValueError
        except ValueError as exc:
            raise DirectoryUnavailable("local_directory_invalid_identity") from exc
        user = self._request("GET", self.admin + "/users/" + key.object_id, missing=True)
        group = self._request("GET", self.admin + "/groups/" + key.object_id, missing=True)
        if user is not None or group is not None:
            raise DirectoryUnavailable("local_directory_changed_during_read")
        return DirectoryObject(key, "user", "Deleted local identity", False, deleted=True)

    def members(self, group: PrincipalKey):
        if group not in self.edges:
            raise DirectoryUnavailable("local_directory_missing_roster")
        return self.edges[group]
