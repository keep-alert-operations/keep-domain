"""Local human sessions: the session cookie, CSRF, the gate and the return path.

Requirements: REV-73; identity configuration 2, 4-5, 8, 10.

Password sign-in (one LDAP bind and a WhoAmI check) lives in ``keep.identity.login``;
the Product API's ``/auth`` routes compose both. A session lasts 24 hours from sign-in
with no idle timeout, refresh or provider credential.
"""

from __future__ import annotations

import hashlib
import secrets
from urllib.parse import unquote, urlsplit

from fastapi import Request

from keep.shared.errors import AppError, unavailable

SESSION_COOKIE = "__Host-keep_session"


class InvalidReturnPath(ValueError):
    """The value is not a local relative path the browser may return to."""


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


def safe_return_path(path: str) -> str:
    """Return ``path`` if it is a local relative path, else raise InvalidReturnPath.

    Browsers normalize backslashes, controls and encoded path separators in ways
    that can turn apparent relative paths into cross-origin redirects.
    """
    if not isinstance(path, str):
        raise InvalidReturnPath("invalid_return_path")
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
        raise InvalidReturnPath("invalid_return_path")
    return path


def authenticate(conn, request: Request, mutation: bool = False):
    """Return (principal, session) under the transaction's authorization guard.

    Keep this transaction open through protected reads or mutation commit. A
    mutation guard serializes identity revocation and grant publication; no age test
    is applied to successfully verified cached directory evidence. A session is
    valid until its absolute deadline; there is no idle timeout (REV-73).
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
           AND s.deployment_epoch=%s""",
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


def _cookie(response, name, value):
    response.set_cookie(name, value, secure=True, httponly=True, samesite="lax", path="/")
    response.headers["Cache-Control"] = "private, no-store"
