import asyncio
import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from authlib.jose import JsonWebKey, JsonWebToken

from keep.identity.oidc import (
    LOGOUT_EVENT,
    OIDCClient,
    OIDCConfig,
    OIDCInvalid,
    OIDCRevoked,
    OIDCUnavailable,
    safe_return_path,
)

NOW = 1800000000
ISSUER = "https://identity.example/realms/keep"


@pytest.fixture
def signing_key():
    return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "key-1"})


def claims(**overrides):
    result = {
        "iss": ISSUER,
        "sub": "subject",
        "aud": "keep-web",
        "sid": "provider-session",
        "iat": NOW,
        "exp": NOW + 300,
        "auth_time": NOW - 100,
        "nonce": "nonce",
        "directory_id": "immutable-123",
        "acr": "company-password",
        "amr": ["pwd"],
    }
    result.update(overrides)
    return result


def sign(key, payload):
    return JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "key-1"}, payload, key).decode()


def make_client(key, token_response=None, required_amr=("pwd",), required_acr="company-password"):
    seen = []
    config = OIDCConfig(
        ISSUER,
        "keep-web",
        "secret",
        "https://app.example/auth/callback",
        "https://app.example/signed-out",
        "company",
        "directory_id",
        "directory-identity",
        required_acr,
        required_amr,
    )

    def handler(request):
        seen.append(request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    **{
                        name: ISSUER + "/" + endpoint
                        for name, endpoint in (
                            ("authorization_endpoint", "auth"),
                            ("token_endpoint", "token"),
                            ("jwks_uri", "keys"),
                            ("end_session_endpoint", "logout"),
                        )
                    },
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        if request.url.path.endswith("/keys"):
            return httpx.Response(200, json={"keys": [key.as_dict(is_private=False)]})
        if request.url.path.endswith("/token"):
            return httpx.Response(
                400 if token_response and "error" in token_response else 200,
                json=token_response or {},
            )
        raise AssertionError("unexpected network request")

    return OIDCClient(config, transport=httpx.MockTransport(handler), clock=lambda: NOW), seen


def test_signed_identity_binding_and_rs256(signing_key):
    client, _ = make_client(signing_key)
    identity = asyncio.run(client.validate_id_token(sign(signing_key, claims()), "nonce"))
    assert identity.directory_object_id == "immutable-123"
    assert identity.auth_time == NOW - 100


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.example"},
        {"aud": "other"},
        {"aud": ["keep-web", "other"]},
        {"azp": "other"},
        {"nonce": "replay"},
        {"exp": NOW - 31},
        {"auth_time": NOW - 86400},
        {"auth_time": NOW + 31},
        {"directory_id": ""},
        {"amr": []},
        {"amr": ["otp"]},
        {"amr": "pwd"},
        {"acr": "weak"},
        {"events": {LOGOUT_EVENT: {}}},
        {"iat": NOW + 31},
    ],
)
def test_invalid_identity_claims_reject(signing_key, overrides):
    client, _ = make_client(signing_key)
    with pytest.raises(OIDCInvalid):
        asyncio.run(client.validate_id_token(sign(signing_key, claims(**overrides)), "nonce"))


def test_pkce_s256_browser_binding_expiry_and_fresh_auth(signing_key):
    client, _ = make_client(signing_key)
    tx = client.new_transaction("/tenants/abc", "x" * 43, fresh=True)
    query = parse_qs(urlsplit(asyncio.run(client.authorization_url(tx))).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [
        base64.urlsafe_b64encode(hashlib.sha256(tx.verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    ]
    assert query["max_age"] == ["0"]
    assert query["state"] == [tx.state]
    assert query["acr_values"] == ["company-password"]
    tx.validate_callback(tx.state, "x" * 43, NOW)
    for state, binding, now in [
        ("wrong", "x" * 43, NOW),
        (tx.state, "y" * 43, NOW),
        (tx.state, "x" * 43, NOW + 600),
    ]:
        with pytest.raises(OIDCInvalid):
            tx.validate_callback(state, binding, now)


def test_configured_stronger_authentication_policy_is_still_enforced(signing_key):
    client, _ = make_client(signing_key, required_amr=("pwd", "otp"))
    with pytest.raises(OIDCInvalid):
        asyncio.run(client.validate_id_token(sign(signing_key, claims()), "nonce"))
    identity = asyncio.run(
        client.validate_id_token(sign(signing_key, claims(amr=["pwd", "otp"])), "nonce")
    )
    assert identity.directory_object_id == "immutable-123"


def test_optional_acr_accepts_any_acr_but_still_requires_password_amr(signing_key):
    # A lightweight provider (e.g. Authelia) need not emit Keycloak's acr value.
    # With required_acr unset, any/absent acr is accepted, but amr=pwd evidence
    # is still mandatory.
    client, _ = make_client(signing_key, required_acr=None)
    for overrides in ({"acr": "weak"}, {}):
        identity = asyncio.run(
            client.validate_id_token(sign(signing_key, claims(**overrides)), "nonce")
        )
        assert identity.directory_object_id == "immutable-123"
    for overrides in ({"amr": []}, {"amr": ["otp"]}, {"amr": "pwd"}):
        with pytest.raises(OIDCInvalid):
            asyncio.run(client.validate_id_token(sign(signing_key, claims(**overrides)), "nonce"))


def test_optional_sid_accepts_absent_or_empty_session_id(signing_key):
    # The provider session id is optional (only used for back-channel logout). An
    # absent or empty sid is accepted and yields an empty OIDCIdentity.sid.
    client, _ = make_client(signing_key)
    for payload in (claims(sid=""), {k: v for k, v in claims().items() if k != "sid"}):
        identity = asyncio.run(client.validate_id_token(sign(signing_key, payload), "nonce"))
        assert identity.sid == ""
        assert identity.directory_object_id == "immutable-123"


def test_optional_acr_omits_acr_values_from_authorization_url(signing_key):
    client, _ = make_client(signing_key, required_acr=None)
    tx = client.new_transaction("/tenants/abc", "x" * 43)
    query = parse_qs(urlsplit(asyncio.run(client.authorization_url(tx))).query)
    assert "acr_values" not in query


@pytest.mark.parametrize(
    "path",
    ["https://evil.example", "//evil.example", "/\\evil", "/%2fevil", "/%255cevil", "/\nlocation"],
)
def test_return_paths_reject_browser_normalization_attacks(path):
    with pytest.raises(OIDCInvalid):
        safe_return_path(path)


def test_logout_requires_purpose_sid_replay_identifier_and_time(signing_key):
    client, _ = make_client(signing_key)
    logout = {
        "iss": ISSUER,
        "aud": "keep-web",
        "iat": NOW,
        "sid": "provider-session",
        "jti": "event-1",
        "events": {LOGOUT_EVENT: {}},
    }
    event = asyncio.run(client.validate_logout_token(sign(signing_key, logout)))
    assert event.fence_until == NOW + 86700
    for override in (
        {"nonce": "wrong-purpose"},
        {"events": {}},
        {"iat": NOW - 301},
        {"sid": ""},
        {"jti": ""},
    ):
        with pytest.raises(OIDCInvalid):
            asyncio.run(client.validate_logout_token(sign(signing_key, {**logout, **override})))


def test_invalid_grant_distinct_from_transport_failure(signing_key):
    client, _ = make_client(signing_key, {"error": "invalid_grant"})
    with pytest.raises(OIDCRevoked):
        asyncio.run(client._tokens(grant_type="refresh_token", refresh_token="revoked"))
    client, _ = make_client(signing_key, {"error": "temporarily_unavailable"})
    with pytest.raises(OIDCUnavailable):
        asyncio.run(client._tokens(grant_type="refresh_token", refresh_token="possibly-valid"))


def test_unknown_kid_refreshes_once_then_rejects(signing_key):
    client, seen = make_client(signing_key)
    asyncio.run(client.validate_id_token(sign(signing_key, claims()), "nonce"))
    private_key = signing_key.as_dict(is_private=True)
    private_key["kid"] = "unknown"
    token = (
        JsonWebToken(["RS256"])
        .encode({"alg": "RS256", "kid": "unknown"}, claims(), private_key)
        .decode()
    )
    with pytest.raises(OIDCInvalid):
        asyncio.run(client.validate_id_token(token, "nonce"))
    assert len([r for r in seen if r.url.path.endswith("/keys")]) == 2


def test_discovery_cannot_move_trusted_issuer_to_another_endpoint(signing_key):
    client, _ = make_client(signing_key)
    with pytest.raises(OIDCUnavailable):
        client._pinned_endpoint("https://evil.example/token")
    with pytest.raises(OIDCUnavailable):
        client._pinned_endpoint("https://identity.example/realms/other/token")
