from __future__ import annotations
import hashlib
import json
import secrets
from fastapi import Request
from appchi.shared.errors import AppError, unavailable
from .oidc import (
    OIDCClient,
    OIDCConfig,
    OIDCIdentity,
    OIDCInvalid,
    OIDCRevoked,
    OIDCUnavailable,
)

SESSION_COOKIE = "__Host-appchi_session"
LOGIN_COOKIE = "__Host-appchi_login"


def _hash(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def _guard(conn, *, exclusive=False):
    conn.execute(
        "SELECT scope FROM authorization_guards WHERE scope='identity' FOR "
        + ("UPDATE" if exclusive else "SHARE")
    )


def require_human_auth(conn):
    row = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='human_auth'"
    ).fetchone()
    if not row or not row["ready"]:
        raise unavailable("human_authorization_gated")


def same_origin(request: Request):
    origin = request.headers.get("origin")
    if origin != request.app.state.settings.public_origin or request.headers.get(
        "sec-fetch-site"
    ) not in (None, "same-origin"):
        raise AppError("origin_rejected", "A same-origin request is required.", 403)


def authenticate(conn, request: Request, mutation: bool = False):
    """Return (principal, session) under the transaction's authorization guard.

    Keep this transaction open through protected reads or mutation commit. A
    mutation guard serializes identity revocation and grant publication; no age test
    is applied to successfully verified cached directory evidence.
    """
    if mutation:
        _guard(conn)
    require_human_auth(conn)
    handle = request.cookies.get(SESSION_COOKIE, "")
    if not handle or len(handle) > 128:
        raise AppError("unauthenticated", "Sign in is required.", 401)
    row = conn.execute(
        """SELECT s.*, p.directory_source,p.object_id,p.kind,p.display_name,p.eligible,p.deleted,
                  p.super_admin,p.evidence_generation,p.verified_at
           FROM auth_sessions s JOIN principals p ON p.id=s.principal_id
           WHERE s.handle_hash=%s AND s.revoked_at IS NULL AND s.absolute_at>clock_timestamp()
           AND s.activity_at>clock_timestamp()-interval '30 minutes' AND s.deployment_epoch=%s""",
        (_hash(handle), request.app.state.settings.deployment_epoch),
    ).fetchone()
    if not row or not row["eligible"] or row["deleted"] or row["kind"] != "user":
        raise AppError("unauthenticated", "Sign in is required.", 401)
    if row["verified_at"] is None or row["evidence_generation"] < 1:
        raise unavailable("directory_evidence_required")
    if mutation:
        same_origin(request)
        csrf = request.headers.get("x-csrf-token", "")
        if (
            not csrf
            or len(csrf) > 128
            or not secrets.compare_digest(_hash(csrf), bytes(row["csrf_hash"]))
        ):
            raise AppError("csrf_rejected", "A valid session CSRF token is required.", 403)
    principal = {
        name: row[name]
        for name in (
            "directory_source",
            "object_id",
            "kind",
            "display_name",
            "eligible",
            "deleted",
            "super_admin",
            "evidence_generation",
            "verified_at",
        )
    }
    principal["id"] = row["principal_id"]
    return principal, row


def oidc_client(request: Request) -> OIDCClient:
    if getattr(request.app.state, "oidc", None) is not None:
        return request.app.state.oidc
    settings = request.app.state.settings
    fields = (
        "oidc_issuer",
        "oidc_client_secret",
        "oidc_directory_source",
        "oidc_directory_id_claim",
        "oidc_directory_scope",
        "oidc_required_acr",
        "oidc_required_amr",
    )
    if not all(getattr(settings, field, None) for field in fields):
        raise unavailable("oidc_configuration_required")
    try:
        config = OIDCConfig(
            settings.oidc_issuer,
            settings.oidc_client_id,
            settings.oidc_client_secret.get_secret_value(),
            settings.public_origin + "/auth/callback",
            settings.public_origin + "/signed-out",
            settings.oidc_directory_source,
            settings.oidc_directory_id_claim,
            settings.oidc_directory_scope,
            settings.oidc_required_acr,
            tuple(settings.oidc_required_amr),
            settings.oidc_ca_file,
        )
        request.app.state.oidc = OIDCClient(config)
    except ValueError:
        raise unavailable("oidc_configuration_invalid") from None
    return request.app.state.oidc


def _protocol_error(exc):
    if isinstance(exc, OIDCUnavailable):
        return unavailable("identity_provider_unavailable")
    return AppError(
        "authentication_rejected", "The authentication response could not be accepted.", 401
    )


def _cookie(response, name, value):
    response.set_cookie(name, value, secure=True, httponly=True, samesite="lax", path="/")
    response.headers["Cache-Control"] = "private, no-store"


async def refresh_session(request: Request):
    """Claim once, exchange outside locks, atomically persist rotated credentials."""
    with request.app.state.db.transaction() as conn:
        principal, session = authenticate(conn, request)
        # A worker may die after consuming a rotating provider token. Never
        # retry its old credential after the bounded exchange lease expires.
        conn.execute(
            """UPDATE auth_sessions SET refresh_uncertain=true,refresh_started_at=NULL
                     WHERE handle_hash=%s AND refresh_started_at<clock_timestamp()-interval '30 seconds'""",
            (session["handle_hash"],),
        )
        claimed = conn.execute(
            """UPDATE auth_sessions SET refresh_generation=refresh_generation+1,
                 refresh_started_at=clock_timestamp() WHERE handle_hash=%s AND refresh_uncertain=false
                 AND refresh_started_at IS NULL AND refresh_at<=clock_timestamp()-interval '4 minutes'
                 RETURNING refresh_generation""",
            (session["handle_hash"],),
        ).fetchone()
    if not claimed:
        return
    generation, handle_hash = claimed["refresh_generation"], bytes(session["handle_hash"])
    cipher = request.app.state.settings.cipher()
    stored = json.loads(
        cipher.open(bytes(session["tokens"]), "session-tokens:" + handle_hash.hex())
    )
    identity = OIDCIdentity(
        session["issuer"],
        session["subject"],
        session["provider_sid"],
        principal["directory_source"],
        principal["object_id"],
        int(session["auth_time"].timestamp()),
        principal["display_name"],
    )
    try:
        refreshed = await oidc_client(request).refresh(stored["refresh_token"], identity)
    except (OIDCInvalid, OIDCUnavailable, AppError) as exc:
        with request.app.state.db.transaction() as conn:
            _guard(conn, exclusive=True)
            if isinstance(exc, (OIDCRevoked, OIDCInvalid)):
                conn.execute(
                    """UPDATE auth_sessions SET revoked_at=clock_timestamp(),tokens=NULL,
                             refresh_started_at=NULL WHERE handle_hash=%s AND refresh_generation=%s""",
                    (handle_hash, generation),
                )
            else:
                conn.execute(
                    """UPDATE auth_sessions SET refresh_uncertain=true,refresh_started_at=NULL
                             WHERE handle_hash=%s AND refresh_generation=%s""",
                    (handle_hash, generation),
                )
        return
    with request.app.state.db.transaction() as conn:
        _guard(conn)
        conn.execute(
            """UPDATE auth_sessions SET tokens=%s,refresh_at=clock_timestamp(),refresh_started_at=NULL
                     WHERE handle_hash=%s AND refresh_generation=%s AND revoked_at IS NULL
                     AND absolute_at>clock_timestamp() AND deployment_epoch=%s""",
            (
                cipher.seal(
                    json.dumps(refreshed.tokens).encode(), "session-tokens:" + handle_hash.hex()
                ),
                handle_hash,
                generation,
                request.app.state.settings.deployment_epoch,
            ),
        )
