"""Read-only restore diagnostics. A collected checkpoint never grants readiness."""

from dataclasses import dataclass
from typing import Literal, get_args, get_type_hints
import re

from appchi.recovery.evidence import Evidence
from appchi.recovery.restore import canonical_id
from appchi.shared.errors import AppError

FAMILIES = get_args(get_type_hints(Evidence)["resource_kind"])
BASE_BLOCKERS = ("authority_baseline_unestablished", "producer_coverage_unestablished")
CAPABILITIES = {
    "human_auth": (
        "permission_reconciliation_unimplemented",
        "fresh_directory_checkpoint_unverified",
    ),
    "v2_ingress": (
        "operator_survival_unverified",
        "credential_reconciliation_unimplemented",
        "accepted_work_boundary_unverified",
    ),
    "recovery": (
        "family_fence_reconciliation_unimplemented",
        "accepted_work_boundary_unverified",
        "clock_authority_unverified",
        "pending_order_unverified",
        "retention_reconciliation_unverified",
    ),
    "search": ("search_rebuild_unverified", "retention_reconciliation_unverified"),
    "correlation": ("pending_order_unverified", "correlation_consumers_unverified"),
    "maintenance": ("pending_order_unverified", "maintenance_consumers_unverified"),
    "audit_retention": ("family_fence_reconciliation_unimplemented",),
}


@dataclass(frozen=True)
class FamilyAssessment:
    family: str
    records: int
    final_records: int
    unresolved_intent_groups: int
    conflicting_terminal_groups: int
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class CapabilityAssessment:
    capability: str
    ready: Literal[False]
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class RestoreAssessment:
    run_id: str
    deployment_epoch: str
    collection_id: str
    collected_records: int
    unsupported_records: int
    families: tuple[FamilyAssessment, ...]
    capabilities: tuple[CapabilityAssessment, ...]
    blockers: tuple[str, ...]
    reopen_permitted: Literal[False] = False
    version: str = "appchi-restore-assessment-v1"


def assess_restore(db, run_id, *, deployment_epoch):
    """Inspect one consistent current collection; do not read or change product content.

    The current schema has no independently established baseline/coverage proof.
    Their absence is always a blocker, even when every staged family is empty.
    Tuple matching below identifies obvious unresolved/conflicting records only;
    it cannot substitute for family-specific attempt-linkage reconciliation.
    """
    canonical_id(run_id)
    canonical_id(deployment_epoch)
    with db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        control = conn.execute("SELECT * FROM restore_control WHERE singleton").fetchone()
        run = conn.execute("SELECT * FROM restore_runs WHERE id=%s", (run_id,)).fetchone()
        if not run:
            raise AppError("not_found", "Recovery operation unavailable.", 404)
        if not control or not control["fenced"] or str(control["run_id"]) != run_id:
            raise AppError(
                "restore_attempt_superseded", "Recovery operation is no longer current.", 409
            )
        if (
            control["deployment_epoch"] != deployment_epoch
            or str(run["deployment_epoch"]) != deployment_epoch
        ):
            raise AppError(
                "deployment_epoch_conflict", "Recovery deployment authority differs.", 409
            )
        if run["state"] != "collected":
            raise AppError(
                "restore_collection_incomplete", "Complete evidence collection is required.", 409
            )
        if (
            not run["collection_id"]
            or not run["snapshot_checkpoint"]
            or not run["evidence_namespace"]
            or any(
                not isinstance(run[key], str) or not re.fullmatch(r"[0-9a-f]{64}", run[key])
                for key in ("binding_digest", "collection_digest")
            )
            or not 0 <= run["collected_count"] <= 1000000
        ):
            raise AppError(
                "restore_collection_invalid", "Collected evidence metadata is inconsistent.", 409
            )
        keys = (run_id, run["collection_id"])
        shape = conn.execute(
            """SELECT count(*) AS n,min(ordinal) AS first,max(ordinal) AS last
            FROM restore_evidence_stage WHERE run_id=%s AND collection_id=%s""",
            keys,
        ).fetchone()
        if shape["n"] != run["collected_count"] or (
            shape["n"] and (shape["first"] != 1 or shape["last"] != shape["n"])
        ):
            raise AppError(
                "restore_collection_invalid", "Collected evidence enumeration is inconsistent.", 409
            )
        # The collector caps staging at one million records; SQL aggregation keeps
        # diagnostic output bounded to the fixed family set rather than raw IDs.
        rows = conn.execute(
            """WITH groups AS (
              SELECT CASE WHEN resource_kind=ANY(%s) THEN resource_kind ELSE 'unsupported' END AS family,
              tenant_id,resource_id,revision,digest,count(*) AS n,
              count(*) FILTER(WHERE state='final') AS finals,
              bool_or(state='intent') AS intent,bool_or(state='final') AS final,
              bool_or(state='cancel') AS cancel
              FROM restore_evidence_stage WHERE run_id=%s AND collection_id=%s
              GROUP BY family,tenant_id,resource_id,revision,digest)
            SELECT family,sum(n) AS n,sum(finals) AS finals,
              count(*) FILTER(WHERE intent AND NOT final AND NOT cancel) AS unresolved,
              count(*) FILTER(WHERE final AND cancel) AS conflicts,
              bool_or(intent) AS has_intent
              FROM groups GROUP BY family""",
            (list(FAMILIES), *keys),
        ).fetchall()
        counts = {row["family"]: row for row in rows}
        families = []
        for family in FAMILIES:
            item = counts.get(family, {})
            blockers = [*BASE_BLOCKERS, "family_reconciliation_unimplemented"]
            if family in ("permission", "credential"):
                blockers.append("authority_producer_unimplemented")
            if item.get("unresolved", 0):
                blockers.append("unresolved_intent")
            if item.get("conflicts", 0):
                blockers.append("conflicting_terminal_evidence")
            if item.get("has_intent"):
                blockers.append("attempt_linkage_unverified")
            families.append(
                FamilyAssessment(
                    family,
                    int(item.get("n", 0)),
                    int(item.get("finals", 0)),
                    int(item.get("unresolved", 0)),
                    int(item.get("conflicts", 0)),
                    tuple(blockers),
                )
            )
        unsupported = int(counts.get("unsupported", {}).get("n", 0))
        blockers = (*BASE_BLOCKERS, "restore_reconciliation_unimplemented")
        if unsupported:
            blockers += ("unsupported_evidence_family",)
        return RestoreAssessment(
            run_id,
            deployment_epoch,
            str(run["collection_id"]),
            shape["n"],
            unsupported,
            tuple(families),
            tuple(
                CapabilityAssessment(name, False, (*BASE_BLOCKERS, *reasons))
                for name, reasons in CAPABILITIES.items()
            ),
            blockers,
        )
