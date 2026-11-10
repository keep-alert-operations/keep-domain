"""Deterministic selection independent of responses, rendering and input payload."""

from hashlib import sha256
from uuid import UUID

from keep.ingestion.native import canonical


def selected(
    *,
    input_id: UUID,
    view_id: UUID,
    view_epoch: int,
    policy_epoch: str,
    kind: str,
    qualification: bool,
) -> bool:
    """Call with trusted server policy, before processing/search success is known."""
    if not isinstance(input_id, UUID) or not isinstance(view_id, UUID):
        raise ValueError("Immutable server input/view UUIDs required")
    if type(view_epoch) is not int or not 0 < view_epoch <= 2**63 - 1:
        raise ValueError("Positive bounded view epoch required")
    if not isinstance(policy_epoch, str) or not 1 <= len(policy_epoch.encode()) <= 256:
        raise ValueError("Stable sampling policy epoch required")
    if kind not in {"incoming", "maintenance_expiry"} or type(qualification) is not bool:
        raise ValueError("Trusted observation kind and qualification policy required")
    if qualification or kind == "maintenance_expiry":
        return True
    digest = sha256(
        canonical(
            ["keep-visibility-sample-v1", policy_epoch, str(input_id), str(view_id), view_epoch]
        )
    ).digest()
    # Exactly one tenth of the hash space, to integer precision. Never Python hash().
    return int.from_bytes(digest, "big") < (1 << 256) // 10
