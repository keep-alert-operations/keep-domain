"""Prove uninterrupted authority for a captured input, never overall eligibility.

The caller keeps the transaction open through use of a proof. Root classifiers
can retain the returned server-only token and recheck in a later transaction.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import re
from uuid import UUID

from keep.access import effective_role
from keep.ingestion.native import canonical
from keep.shared.errors import unavailable
from keep.shared.transactions import coordinator
from keep.serialization import wire

SCHEMA = "keep-visibility-authority-v1"


@dataclass(frozen=True)
class AuthorityToken:
    tenant: UUID
    input_id: UUID
    view_id: UUID
    view_epoch: int
    control_checkpoint: int
    input_fingerprint: str
    snapshot_digest: str


@dataclass(frozen=True)
class AuthorityProof:
    proven: bool
    reason: str
    token: AuthorityToken | None = None


def _binding(principal, session):
    return sha256(
        canonical(
            wire(
                [
                    "keep-visibility-session-binding-v1",
                    bytes(session["handle_hash"]).hex(),
                    principal["id"],
                    principal["directory_source"],
                    principal["object_id"],
                    session["principal_id"],
                    session["issuer"],
                    session["subject"],
                    session["provider_sid"],
                    session["auth_time"],
                    session["absolute_at"],
                    session["deployment_epoch"],
                ]
            )
        )
    ).hexdigest()


def _fences(conn, tenant):
    return conn.execute(
        """SELECT t.revision AS tenant_revision,a.directory_revision,
        coalesce((SELECT max(semantic_revision) FROM directory_verifications),0) AS directory_semantic_revision,
        g.ready AS human_auth_ready,g.generation AS human_auth_generation
        FROM tenants t CROSS JOIN authorization_guards a CROSS JOIN capability_gates g
        WHERE t.id=%s AND a.scope='identity' AND g.capability='human_auth' FOR SHARE OF g""",
        (tenant,),
    ).fetchone()


def capture_authority(conn, *, tenant, principal, session, role, now):
    """Caller already owns identity guard, then coordinator, after authorization."""
    fences = _fences(conn, tenant)
    if not fences or not fences["human_auth_ready"]:
        raise unavailable("human_authorization_gated")
    bound = min(session["absolute_at"], session["activity_at"] + timedelta(minutes=30))
    if now >= bound:
        raise unavailable("visibility_session_boundary_unproven")
    return wire(
        {
            "schema": SCHEMA,
            **{key: value for key, value in fences.items() if key != "human_auth_ready"},
            "principal_evidence_generation": principal["evidence_generation"],
            "role": role,
            "super_admin": principal["super_admin"],
            "session_authorized_until": bound,
            "session_activity_at": session["activity_at"],
            "session_absolute_at": session["absolute_at"],
            "session_binding_digest": _binding(principal, session),
            "captured_at": now,
        }
    )


def _counter(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise ValueError("Canonical authority counter required")
    result = int(value)
    if result >= 2**63:
        raise ValueError("Bounded authority counter required")
    return result


def _time(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("Authoritative timezone required")
    return result


def prove_authority(conn, *, tenant, input_id, view_id, view_epoch):
    """Only unchanged guarded authority can prove the original input boundary.

    Missing or changed proof is unclassified. Even a known later revocation must
    never be reinterpreted as absence of an originally eligible observation.
    Call before acquiring any coordinator/domain lock in a new transaction.
    """
    tenant, input_id, view_id = (UUID(str(value)) for value in (tenant, input_id, view_id))
    if type(view_epoch) is not int or not 0 < view_epoch < 2**63:
        raise ValueError("Positive bounded view epoch required")
    conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE")
    _, now = coordinator(conn, tenant)
    row = conn.execute(
        """SELECT i.started_at,i.kind,i.disposition,i.deployment_epoch,i.fingerprint,
        c.control_checkpoint,v.recorded_at,v.session_hash,v.snapshot
        FROM visibility_candidates c JOIN visibility_inputs i ON i.tenant_id=c.tenant_id AND i.id=c.input_id
        JOIN visibility_view_controls v ON v.tenant_id=c.tenant_id AND v.checkpoint=c.control_checkpoint
        WHERE c.tenant_id=%s AND c.input_id=%s AND c.view_id=%s AND c.view_epoch=%s""",
        (tenant, input_id, view_id, view_epoch),
    ).fetchone()
    if not row:
        return AuthorityProof(False, "authority_candidate_missing")
    snapshot = row["snapshot"]
    authority = snapshot.get("authority") if isinstance(snapshot, dict) else None
    if not isinstance(authority, dict) or authority.get("schema") != SCHEMA:
        return AuthorityProof(False, "authority_snapshot_legacy_or_missing")
    try:
        principal_id = UUID(snapshot["principal_id"])
        counters = {
            key: _counter(authority[key])
            for key in (
                "tenant_revision",
                "directory_revision",
                "directory_semantic_revision",
                "human_auth_generation",
                "principal_evidence_generation",
            )
        }
        captured_at = _time(authority["captured_at"])
        original_activity = _time(authority["session_activity_at"])
        original_absolute = _time(authority["session_absolute_at"])
        original_bound = _time(authority["session_authorized_until"])
        valid_shape = (
            snapshot["id"] == str(view_id)
            and snapshot["tenant_id"] == str(tenant)
            and _counter(snapshot["view_epoch"]) == view_epoch
            and _counter(snapshot["checkpoint"]) == row["control_checkpoint"]
            and isinstance(authority["super_admin"], bool)
            and authority["role"] in {"view", "edit", "admin"}
            and re.fullmatch(r"[0-9a-f]{64}", authority["session_binding_digest"])
            and captured_at == row["recorded_at"]
            and original_bound == min(original_absolute, original_activity + timedelta(minutes=30))
        )
    except (KeyError, ValueError, TypeError, OverflowError):
        return AuthorityProof(False, "authority_snapshot_invalid")
    if not valid_shape:
        return AuthorityProof(False, "authority_snapshot_invalid")
    if row["deployment_epoch"] != snapshot.get("deployment_epoch"):
        return AuthorityProof(False, "authority_deployment_changed")
    if (
        row["disposition"] != "pending"
        or row["started_at"] > now
        or row["started_at"] < captured_at
        or row["kind"] == "maintenance_expiry"
        and row["started_at"] == captured_at
    ):
        return AuthorityProof(False, "authority_original_boundary_unproven")
    if row["started_at"] >= original_bound:
        return AuthorityProof(False, "authority_original_session_bound_exceeded")
    fences = _fences(conn, tenant)
    if not fences or not fences["human_auth_ready"]:
        return AuthorityProof(False, "authority_gate_unavailable")
    for key in (
        "tenant_revision",
        "directory_revision",
        "directory_semantic_revision",
        "human_auth_generation",
    ):
        if counters[key] != fences[key]:
            return AuthorityProof(False, "authority_" + key + "_changed")
    principal = conn.execute("SELECT * FROM principals WHERE id=%s", (principal_id,)).fetchone()
    session = conn.execute(
        "SELECT * FROM auth_sessions WHERE handle_hash=%s", (row["session_hash"],)
    ).fetchone()
    if not principal or not session:
        return AuthorityProof(False, "authority_session_or_principal_missing")
    if (
        principal["kind"] != "user"
        or not principal["eligible"]
        or principal["deleted"]
        or principal["verified_at"] is None
        or principal["evidence_generation"] < 1
        or principal["evidence_generation"] != counters["principal_evidence_generation"]
        or principal["super_admin"] != authority["super_admin"]
    ):
        return AuthorityProof(False, "authority_principal_changed")
    if (
        session["principal_id"] != principal_id
        or session["deployment_epoch"] != row["deployment_epoch"]
        or _binding(principal, session) != authority["session_binding_digest"]
        or session["absolute_at"] != original_absolute
        or session["activity_at"] < original_activity
    ):
        return AuthorityProof(False, "authority_session_binding_changed")
    if (
        session["revoked_at"] is not None
        or now >= session["absolute_at"]
        or now >= session["activity_at"] + timedelta(minutes=30)
    ):
        return AuthorityProof(False, "authority_session_no_longer_valid")
    if effective_role(conn, principal, tenant) != authority["role"]:
        return AuthorityProof(False, "authority_effective_role_changed")
    return AuthorityProof(
        True,
        "uninterrupted_authority",
        AuthorityToken(
            tenant,
            input_id,
            view_id,
            view_epoch,
            row["control_checkpoint"],
            bytes(row["fingerprint"]).hex(),
            sha256(canonical(snapshot)).hexdigest(),
        ),
    )


def recheck_authority(conn, token: AuthorityToken):
    proof = prove_authority(
        conn,
        tenant=token.tenant,
        input_id=token.input_id,
        view_id=token.view_id,
        view_epoch=token.view_epoch,
    )
    if proof.proven and proof.token != token:
        return AuthorityProof(False, "authority_proof_identity_changed")
    return proof
