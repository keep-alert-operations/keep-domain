"""Backend OIDC code/PKCE, signed identity and logout validation using Authlib.

Persistence owns one-use transactions, session rotation, binding uniqueness,
refresh serialization and logout replay fences. This adapter never admits users
from a token alone and never treats provider transport errors as revocation.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.base_client.errors import OAuthError
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from authlib.oauth2.rfc6749.errors import OAuth2Error

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class OIDCInvalid(Exception):
    """Untrusted/invalid protocol input; caller must not establish a session."""


class OIDCUnavailable(Exception):
    """Ambiguous transport/provider failure; not evidence of revocation."""


class OIDCRevoked(OIDCInvalid):
    """Definitive invalid_grant; corresponding local session must end."""


class _LimitedStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, limit: int):
        self.stream, self.limit = stream, limit

    async def __aiter__(self):
        size = 0
        async for chunk in self.stream:
            size += len(chunk)
            if size > self.limit:
                raise OIDCUnavailable("provider_response_limit")
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class _LimitedTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.AsyncBaseTransport, limit: int):
        self.transport, self.limit = transport, limit

    async def handle_async_request(self, request):
        response = await self.transport.handle_async_request(request)
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=_LimitedStream(response.stream, self.limit),
            extensions=response.extensions,
        )

    async def aclose(self):
        await self.transport.aclose()


def _https_url(value: str) -> bool:
    url = urlsplit(value)
    return (
        url.scheme == "https"
        and bool(url.hostname)
        and not url.username
        and not url.password
        and not url.fragment
    )


def safe_return_path(path: str) -> str:
    # Browsers normalize backslashes, controls and encoded path separators in
    # ways that can turn apparent relative paths into cross-origin redirects.
    from urllib.parse import unquote

    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or not decoded.startswith("/")
        or decoded.startswith("//")
        or "\\" in decoded
        or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
        or urlsplit(path).scheme
        or urlsplit(path).netloc
        or len(path) > 2048
    ):
        raise OIDCInvalid("invalid_return_path")
    return path


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str
    post_logout_redirect_uri: str
    directory_source: str
    directory_id_claim: str
    directory_scope: str
    # Protected authentication mapper values must be explicitly configured.
    # required_acr is optional: lightweight providers (e.g. Authelia) emit an acr
    # that differs from Keycloak's, so acr is only enforced when a value is set.
    # amr (password evidence) remains mandatory.
    required_acr: str | None
    required_amr: tuple[str, ...]
    ca_file: str | None = None
    timeout_seconds: float = 5
    max_response_bytes: int = 1048576

    def __post_init__(self) -> None:
        if not all(
            _https_url(x) for x in (self.issuer, self.redirect_uri, self.post_logout_redirect_uri)
        ):
            raise ValueError("OIDC issuer and exact redirects require HTTPS")
        if urlsplit(self.issuer).query or self.issuer.endswith("/"):
            raise ValueError("OIDC issuer must be its exact canonical URL")
        if urlsplit(self.redirect_uri).netloc != urlsplit(self.post_logout_redirect_uri).netloc:
            raise ValueError("OIDC redirects must share the application origin")
        if not all(
            (
                self.client_id,
                self.client_secret,
                self.directory_source,
                self.directory_id_claim,
                self.directory_scope,
                self.required_amr,
            )
        ):
            raise ValueError("explicit protected directory and authentication mapping required")
        if not 0 < self.timeout_seconds <= 10 or not 1024 <= self.max_response_bytes <= 1048576:
            raise ValueError("invalid OIDC network limits")


@dataclass(frozen=True)
class LoginTransaction:
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    verifier: str = field(repr=False)
    browser_binding_hash: str = field(repr=False)
    return_path: str
    created_at: int
    expires_at: int
    max_age: int

    @property
    def state_hash(self) -> str:
        return hashlib.sha256(self.state.encode()).hexdigest()

    def validate_callback(self, state: str, browser_binding: str, now: int) -> None:
        if (
            now >= self.expires_at
            or now < self.created_at
            or not secrets.compare_digest(state, self.state)
            or not secrets.compare_digest(
                hashlib.sha256(browser_binding.encode()).hexdigest(), self.browser_binding_hash
            )
        ):
            raise OIDCInvalid("invalid_login_transaction")


@dataclass(frozen=True)
class OIDCIdentity:
    issuer: str
    subject: str
    sid: str
    directory_source: str
    directory_object_id: str
    auth_time: int
    display_name: str


@dataclass(frozen=True)
class TokenSet:
    identity: OIDCIdentity
    tokens: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class LogoutEvent:
    issuer: str
    sid: str
    subject: str | None
    jti: str
    issued_at: int
    fence_until: int


class OIDCClient:
    def __init__(
        self,
        config: OIDCConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.config, self.transport, self.clock = config, transport, clock
        self._metadata: dict | None = None
        self._jwks: dict | None = None
        self._jwks_at = 0.0
        self._jwt = JsonWebToken(["RS256"])

    def _http_options(self) -> dict:
        import ssl

        context = ssl.create_default_context(cafile=self.config.ca_file)
        transport = self.transport or httpx.AsyncHTTPTransport(
            verify=context, trust_env=False, retries=0
        )
        return {
            "timeout": httpx.Timeout(self.config.timeout_seconds),
            "follow_redirects": False,
            "verify": context,
            "transport": _LimitedTransport(transport, self.config.max_response_bytes),
            "trust_env": False,
        }

    async def _get_json(self, url: str) -> dict:
        try:
            return await asyncio.wait_for(
                self._get_json_response(url), timeout=self.config.timeout_seconds
            )
        except TimeoutError:
            raise OIDCUnavailable("provider_deadline") from None

    async def _get_json_response(self, url: str) -> dict:
        try:
            async with httpx.AsyncClient(**self._http_options()) as client:
                async with client.stream(
                    "GET", url, headers={"Accept": "application/json"}
                ) as response:
                    response.raise_for_status()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self.config.max_response_bytes:
                            raise OIDCUnavailable("provider_response_limit")
                    result = json.loads(body)
                    if not isinstance(result, dict):
                        raise OIDCUnavailable("provider_response_invalid")
                    return result
        except (httpx.HTTPError, ValueError):
            raise OIDCUnavailable("provider_unavailable") from None

    def _pinned_endpoint(self, endpoint: Any) -> str:
        if not isinstance(endpoint, str) or not _https_url(endpoint):
            raise OIDCUnavailable("provider_endpoint_invalid")
        issuer, target = urlsplit(self.config.issuer), urlsplit(endpoint)
        if (
            target.netloc != issuer.netloc
            or target.query
            or not target.path.startswith(issuer.path.rstrip("/") + "/")
        ):
            raise OIDCUnavailable("provider_endpoint_outside_pinned_issuer")
        return endpoint

    async def metadata(self) -> dict:
        if self._metadata is None:
            metadata = await self._get_json(
                self.config.issuer + "/.well-known/openid-configuration"
            )
            if metadata.get("issuer") != self.config.issuer:
                raise OIDCUnavailable("provider_issuer_mismatch")
            for name in (
                "authorization_endpoint",
                "token_endpoint",
                "jwks_uri",
                "end_session_endpoint",
            ):
                self._pinned_endpoint(metadata.get(name))
            if "RS256" not in metadata.get("id_token_signing_alg_values_supported", []):
                raise OIDCUnavailable("provider_signing_contract_missing")
            self._metadata = metadata
        return self._metadata

    def new_transaction(
        self, return_path: str, browser_binding: str, *, fresh: bool = False
    ) -> LoginTransaction:
        if len(browser_binding) < 32:
            raise ValueError("browser binding requires a random 256-bit handle")
        now = int(self.clock())
        return LoginTransaction(
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(48),
            hashlib.sha256(browser_binding.encode()).hexdigest(),
            safe_return_path(return_path),
            now,
            now + 600,
            0 if fresh else 86400,
        )

    async def authorization_url(self, transaction: LoginTransaction) -> str:
        metadata = await self.metadata()
        async with AsyncOAuth2Client(
            self.config.client_id,
            self.config.client_secret,
            redirect_uri=self.config.redirect_uri,
            code_challenge_method="S256",
            **self._http_options(),
        ) as client:
            optional = {"acr_values": self.config.required_acr} if self.config.required_acr else {}
            uri, _ = client.create_authorization_url(
                metadata["authorization_endpoint"],
                state=transaction.state,
                nonce=transaction.nonce,
                code_verifier=transaction.verifier,
                scope=f"openid profile {self.config.directory_scope}",
                max_age=transaction.max_age,
                **optional,
            )
            return uri

    async def _signed_claims(self, token: str, *, logout: bool = False) -> dict:
        if not isinstance(token, str) or len(token) > 32768:
            raise OIDCInvalid("invalid_signed_token")
        try:
            header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==="))
            kid = header.get("kid")
            if (
                header.get("alg") != "RS256"
                or not isinstance(kid, str)
                or not kid
                or header.get("crit")
            ):
                raise OIDCInvalid("invalid_signing_header")
        except (ValueError, IndexError, AttributeError):
            raise OIDCInvalid("invalid_signing_header") from None
        metadata = await self.metadata()
        fetched = False
        if self._jwks is None or self.clock() - self._jwks_at >= 300:
            self._jwks = await self._get_json(metadata["jwks_uri"])
            self._jwks_at = self.clock()
            fetched = True
        keys = self._matching_keys(kid)
        if not keys and not fetched:
            self._jwks = await self._get_json(metadata["jwks_uri"])
            self._jwks_at = self.clock()
            keys = self._matching_keys(kid)
        if len(keys) != 1:
            raise OIDCInvalid("unverifiable_signing_key")
        required = {name: {"essential": True} for name in ("iss", "aud", "iat")}
        required["iss"]["value"] = self.config.issuer
        if not logout:
            required["exp"] = {"essential": True}
        try:
            claims = self._jwt.decode(token, keys[0], claims_options=required)
            claims.validate(now=int(self.clock()), leeway=30)
        except (JoseError, ValueError, TypeError, KeyError):
            raise OIDCInvalid("invalid_signed_token") from None
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud
        if (
            not isinstance(audiences, list)
            or not audiences
            or any(not isinstance(a, str) for a in audiences)
            or self.config.client_id not in audiences
            or (len(audiences) > 1 and claims.get("azp") != self.config.client_id)
            or ("azp" in claims and claims["azp"] != self.config.client_id)
        ):
            raise OIDCInvalid("invalid_token_audience")
        for name in ("iat", "exp", "nbf"):
            if name in claims and (
                not isinstance(claims[name], int) or isinstance(claims[name], bool)
            ):
                raise OIDCInvalid("invalid_token_time")
        return dict(claims)

    def _matching_keys(self, kid: str) -> list[dict]:
        keys = (self._jwks or {}).get("keys", [])
        if not isinstance(keys, list) or len(keys) > 100:
            raise OIDCUnavailable("provider_keyset_invalid")
        return [
            k
            for k in keys
            if isinstance(k, dict)
            and k.get("kid") == kid
            and k.get("kty") == "RSA"
            and k.get("use", "sig") == "sig"
            and k.get("alg", "RS256") == "RS256"
            and "d" not in k
            and ("key_ops" not in k or "verify" in k["key_ops"])
        ]

    async def validate_id_token(
        self,
        token: str,
        nonce: str | None,
        *,
        max_age: int = 86400,
        requested_at: int | None = None,
    ) -> OIDCIdentity:
        claims = await self._signed_claims(token)
        if nonce is not None and (
            not isinstance(claims.get("nonce"), str)
            or not secrets.compare_digest(claims["nonce"], nonce)
        ):
            raise OIDCInvalid("invalid_token_nonce")
        if "events" in claims:
            raise OIDCInvalid("wrong_token_purpose")
        auth_time = claims.get("auth_time")
        now = int(self.clock())
        if (
            not isinstance(auth_time, int)
            or isinstance(auth_time, bool)
            or auth_time > now + 30
            or now >= auth_time + 86400
            or (requested_at is not None and auth_time < requested_at - max_age - 30)
        ):
            raise OIDCInvalid("invalid_authentication_time")
        if self.config.required_acr is not None and claims.get("acr") != self.config.required_acr:
            raise OIDCInvalid("mfa_evidence_required")
        if not isinstance(claims.get("amr"), list) or not set(self.config.required_amr).issubset(
            claims["amr"]
        ):
            raise OIDCInvalid("mfa_evidence_required")
        for name in ("sub", "sid", self.config.directory_id_claim):
            if not isinstance(claims.get(name), str) or not claims[name] or len(claims[name]) > 512:
                raise OIDCInvalid("immutable_identity_binding_required")
        return OIDCIdentity(
            self.config.issuer,
            claims["sub"],
            claims["sid"],
            self.config.directory_source,
            claims[self.config.directory_id_claim],
            auth_time,
            str(claims.get("name", ""))[:512],
        )

    async def _tokens(self, **kwargs: Any) -> dict:
        try:
            return await asyncio.wait_for(
                self._tokens_response(**kwargs), timeout=self.config.timeout_seconds
            )
        except TimeoutError:
            raise OIDCUnavailable("provider_deadline") from None

    async def _tokens_response(self, **kwargs: Any) -> dict:
        metadata = await self.metadata()
        try:
            async with AsyncOAuth2Client(
                self.config.client_id,
                self.config.client_secret,
                redirect_uri=self.config.redirect_uri,
                token_endpoint_auth_method="client_secret_basic",
                **self._http_options(),
            ) as client:
                token = await client.fetch_token(metadata["token_endpoint"], **kwargs)
                if (
                    not isinstance(token.get("access_token"), str)
                    or not isinstance(token.get("refresh_token"), str)
                    or token.get("token_type", "").lower() != "bearer"
                ):
                    raise OIDCUnavailable("provider_token_response_incomplete")
                return dict(token)
        except (OAuth2Error, OAuthError) as exc:
            if exc.error == "invalid_grant":
                raise OIDCRevoked("provider_grant_revoked") from None
            raise OIDCUnavailable("provider_exchange_failed") from None
        except (httpx.HTTPError, ValueError, KeyError):
            raise OIDCUnavailable("provider_exchange_unavailable") from None

    async def exchange(self, code: str, transaction: LoginTransaction) -> TokenSet:
        if int(self.clock()) >= transaction.expires_at:
            raise OIDCInvalid("login_transaction_expired")
        tokens = await self._tokens(
            grant_type="authorization_code", code=code, code_verifier=transaction.verifier
        )
        identity = await self.validate_id_token(
            tokens.get("id_token"),
            transaction.nonce,
            max_age=transaction.max_age,
            requested_at=transaction.created_at,
        )
        return TokenSet(identity, tokens)

    async def refresh(self, refresh_token: str, binding: OIDCIdentity) -> TokenSet:
        tokens = await self._tokens(grant_type="refresh_token", refresh_token=refresh_token)
        identity = await self.validate_id_token(tokens.get("id_token"), None)
        if (
            identity.issuer,
            identity.subject,
            identity.sid,
            identity.directory_source,
            identity.directory_object_id,
            identity.auth_time,
        ) != (
            binding.issuer,
            binding.subject,
            binding.sid,
            binding.directory_source,
            binding.directory_object_id,
            binding.auth_time,
        ):
            raise OIDCInvalid("refresh_identity_binding_conflict")
        return TokenSet(identity, tokens)

    async def validate_logout_token(self, token: str) -> LogoutEvent:
        claims = await self._signed_claims(token, logout=True)
        now = int(self.clock())
        if (
            "nonce" in claims
            or claims.get("events") != {LOGOUT_EVENT: {}}
            or claims["iat"] < now - 300
            or claims["iat"] > now + 30
        ):
            raise OIDCInvalid("invalid_logout_purpose_or_time")
        for name in ("sid", "jti"):
            if not isinstance(claims.get(name), str) or not claims[name] or len(claims[name]) > 512:
                raise OIDCInvalid("invalid_logout_binding")
        if "sub" in claims and (not isinstance(claims["sub"], str) or not claims["sub"]):
            raise OIDCInvalid("invalid_logout_binding")
        return LogoutEvent(
            self.config.issuer,
            claims["sid"],
            claims.get("sub"),
            claims["jti"],
            claims["iat"],
            max(now, claims["iat"]) + 86400 + 300,
        )

    async def logout_url(self, id_token_hint: str) -> str:
        metadata = await self.metadata()
        return (
            metadata["end_session_endpoint"]
            + "?"
            + urlencode(
                {
                    "id_token_hint": id_token_hint,
                    "post_logout_redirect_uri": self.config.post_logout_redirect_uri,
                    "client_id": self.config.client_id,
                }
            )
        )
