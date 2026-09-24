"""Durable original boundaries and resumable sampled candidate inventory.

Trusted producers pass their existing transaction; helpers never commit it.
Nothing in this module proves eligibility, query correctness, rendering or success.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import re
from uuid import UUID

from psycopg.types.json import Jsonb

from appchi.ingestion.native import canonical
from appchi.shared.errors import AppError
from appchi.shared.transactions import coordinator, wire
from .sampling import selected


@dataclass(frozen=True)
class InputLimits:
    max_tenant_inputs: int
    max_tenant_candidates: int
    max_tenant_applications: int
    max_tenant_application_bytes: int
    max_application_bytes: int
    max_views_per_turn: int

    def __post_init__(self):
        if any(
            type(value) is not int or not 0 < value < 2**63 - 1 for value in vars(self).values()
        ):
            raise ValueError("Explicit positive bounded visibility allocations required")
        if self.max_application_bytes > self.max_tenant_application_bytes:
            raise ValueError("Application allocation exceeds tenant allocation")
        if self.max_views_per_turn > 200:
            raise ValueError("One expansion transaction may inspect at most 200 views")


@dataclass(frozen=True)
class SamplingPolicy:
    epoch: str
    qualification: bool
    deployment_epoch: str

    def __post_init__(self):
        if (
            not isinstance(self.epoch, str)
            or not 1 <= len(self.epoch.encode()) <= 256
            or type(self.qualification) is not bool
        ):
            raise ValueError("Immutable server sampling policy required")
        if (
            not isinstance(self.deployment_epoch, str)
            or not 1 <= len(self.deployment_epoch.encode()) <= 256
        ):
            raise ValueError("Explicit deployment epoch required")


def _uuid(value):
    if not isinstance(value, UUID) and (not isinstance(value, str) or str(UUID(value)) != value):
        raise ValueError("Canonical UUID required")
    return UUID(str(value))


def _time(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Original timestamp must be timezone-aware")
    return value


def registry_checkpoint(conn, tenant):
    """Call while holding the tenant coordinator, without enumerating views."""
    row = conn.execute(
        "SELECT checkpoint FROM visibility_registry_heads WHERE tenant_id=%s", (tenant,)
    ).fetchone()
    return row["checkpoint"] if row else 0


def _capacity(conn, tenant):
    conn.execute(
        "INSERT INTO visibility_input_capacity(tenant_id) VALUES(%s) ON CONFLICT DO NOTHING",
        (tenant,),
    )
    return conn.execute(
        "SELECT * FROM visibility_input_capacity WHERE tenant_id=%s FOR UPDATE", (tenant,)
    ).fetchone()


def record_input(
    conn,
    *,
    tenant,
    input_id,
    kind,
    started_at,
    original_order,
    registry_checkpoint: int,
    policy: SamplingPolicy,
    limits: InputLimits,
    schedule=None,
):
    """Insert beside durable admission/schedule work, before processing succeeds.

    On hard seed exhaustion returns capacity_gap, never throws to implicitly
    reject an otherwise valid admission. Producer must account for that outcome.
    Gap attempts cannot be deduplicated without storing additional identities.
    """
    tenant, input_id = _uuid(tenant), _uuid(input_id)
    _time(started_at)
    if (
        type(original_order) is not int
        or not 0 <= original_order < 2**63 - 1
        or type(registry_checkpoint) is not int
        or not 0 <= registry_checkpoint < 2**63 - 1
    ):
        raise ValueError("Bounded original order/checkpoint required")
    if kind == "incoming":
        if original_order == 0 or schedule is not None:
            raise ValueError("Incoming input requires positive original order and no schedule")
    elif kind == "maintenance_expiry":
        if (
            original_order != 0
            or not isinstance(schedule, dict)
            or set(schedule) != {"window_id", "revision", "generation"}
        ):
            raise ValueError("Expiry requires scheduled order zero and exact schedule identity")
        schedule = {**schedule, "window_id": str(_uuid(schedule["window_id"]))}
        if any(
            type(schedule[k]) is not int or not 0 < schedule[k] < 2**63 - 1
            for k in ("revision", "generation")
        ):
            raise ValueError("Positive schedule revision/generation required")
    else:
        raise ValueError("Known visibility input kind required")
    fingerprint = sha256(
        canonical(
            wire(
                [
                    str(tenant),
                    str(input_id),
                    kind,
                    started_at,
                    original_order,
                    registry_checkpoint,
                    policy.epoch,
                    policy.qualification,
                    policy.deployment_epoch,
                    schedule,
                ]
            )
        )
    ).digest()
    _, now = coordinator(conn, tenant)
    old = conn.execute(
        "SELECT * FROM visibility_inputs WHERE tenant_id=%s AND id=%s", (tenant, input_id)
    ).fetchone()
    if old:
        if bytes(old["fingerprint"]) != fingerprint:
            raise AppError("visibility_input_conflict", "Original input metadata differs.", 409)
        return {"status": "existing", "input": old}
    current = conn.execute(
        "SELECT checkpoint FROM visibility_registry_heads WHERE tenant_id=%s", (tenant,)
    ).fetchone()
    if registry_checkpoint != (current["checkpoint"] if current else 0):
        raise ValueError("Capture the current registry checkpoint under the producer coordinator")
    if kind == "incoming" and started_at > now:
        raise ValueError("Incoming original receipt cannot be in the future")
    capacity = _capacity(conn, tenant)
    if capacity["inputs"] >= limits.max_tenant_inputs:
        conn.execute(
            """UPDATE visibility_input_capacity SET seed_gap_attempts=seed_gap_attempts+1,
          first_gap_started_at=least(first_gap_started_at,%s),last_gap_started_at=greatest(last_gap_started_at,%s)
          WHERE tenant_id=%s""",
            (started_at, started_at, tenant),
        )
        return {"status": "capacity_gap", "input": None, "reason": "seed_allocation_exhausted"}
    row = conn.execute(
        """INSERT INTO visibility_inputs(tenant_id,id,kind,started_at,original_order,deadline_at,
       seed_checkpoint,cohort_checkpoint,policy_epoch,qualification,deployment_epoch,allocations,sampling_algorithm,schedule,fingerprint)
       VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'appchi-visibility-sample-v1',%s,%s) RETURNING *""",
        (
            tenant,
            input_id,
            kind,
            started_at,
            original_order,
            started_at + timedelta(seconds=5),
            registry_checkpoint,
            registry_checkpoint if kind == "incoming" else None,
            policy.epoch,
            policy.qualification,
            policy.deployment_epoch,
            Jsonb(asdict(limits)),
            Jsonb(schedule) if schedule is not None else None,
            fingerprint,
        ),
    ).fetchone()
    conn.execute(
        "UPDATE visibility_input_capacity SET inputs=inputs+1 WHERE tenant_id=%s", (tenant,)
    )
    return {"status": "recorded", "input": row}


def seal_expiry_boundary(conn, *, tenant, input_id):
    """Seal once at/after original scheduled end, before expanding its cohort."""
    _, now = coordinator(conn, tenant)
    row = conn.execute(
        "SELECT * FROM visibility_inputs WHERE tenant_id=%s AND id=%s FOR UPDATE",
        (tenant, input_id),
    ).fetchone()
    if not row or row["kind"] != "maintenance_expiry":
        raise ValueError("Scheduled visibility seed required")
    if row["cohort_checkpoint"] is not None:
        return row
    if now < row["started_at"] or row["disposition"] != "pending":
        return row
    return conn.execute(
        """UPDATE visibility_inputs SET cohort_checkpoint=%s WHERE tenant_id=%s AND id=%s RETURNING *""",
        (registry_checkpoint(conn, tenant), tenant, input_id),
    ).fetchone()


def dispose_schedule(conn, *, tenant, input_id, generation, disposition, evidence_reference):
    if (
        disposition not in {"cancelled", "superseded"}
        or type(generation) is not int
        or not 0 < generation < 2**63 - 1
        or not isinstance(evidence_reference, str)
        or not 1 <= len(evidence_reference.encode()) <= 1024
    ):
        raise ValueError("Trusted bounded schedule disposition proof required")
    _, now = coordinator(conn, tenant)
    row = conn.execute(
        "SELECT * FROM visibility_inputs WHERE tenant_id=%s AND id=%s FOR UPDATE",
        (tenant, input_id),
    ).fetchone()
    if (
        not row
        or row["kind"] != "maintenance_expiry"
        or row["schedule"]["generation"] != generation
    ):
        raise ValueError("Matching schedule seed required")
    proof = {"generation": generation, "reference": evidence_reference}
    if row["disposition"] != "pending":
        if row["disposition"] != disposition or row["disposition_proof"]["evidence"] != proof:
            raise AppError("visibility_input_conflict", "Schedule disposition differs.", 409)
        return row
    if now >= row["started_at"]:
        raise AppError(
            "visibility_boundary_passed", "A due expiry cannot be retroactively cancelled.", 409
        )
    return conn.execute(
        "UPDATE visibility_inputs SET disposition=%s,disposition_proof=%s WHERE tenant_id=%s AND id=%s RETURNING *",
        (disposition, Jsonb({"recorded_at": wire(now), "evidence": proof}), tenant, input_id),
    ).fetchone()


def link_application(
    conn,
    *,
    tenant,
    input_id,
    application_id,
    alert_id,
    before,
    after,
    projection_seq,
    projection_version,
    disposition,
    limits: InputLimits | None = None,
    error_code=None,
    journal_order=None,
    source_event_id=None,
):
    """Record digests and non-owning locators, never copies of alert content.

    Future classifiers must preserve a coverage gap if the referenced product
    proof has expired; these references deliberately cannot block product purge.
    """
    tenant, input_id, application_id = map(_uuid, (tenant, input_id, application_id))
    if disposition == "rejected":
        if (
            any(
                value is not None
                for value in (
                    alert_id,
                    before,
                    after,
                    projection_seq,
                    projection_version,
                    journal_order,
                    source_event_id,
                )
            )
            or not isinstance(error_code, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", error_code)
        ):
            raise ValueError(
                "Rejected processing requires only a bounded error code, no fabricated alert/projection"
            )
    else:
        alert_id = _uuid(alert_id)
        if before is not None and not isinstance(before, dict) or not isinstance(after, dict):
            raise ValueError("Before/after proof snapshots required")
        if (
            disposition not in {"applied", "unchanged"}
            or type(projection_seq) is not int
            or not 0 <= projection_seq < 2**63 - 1
            or type(projection_version) is not int
            or not 0 < projection_version < 2**63 - 1
            or error_code is not None
        ):
            raise ValueError("Application disposition and bounded projection linkage required")
        if journal_order is not None and (
            type(journal_order) is not int or not 0 < journal_order < 2**63 - 1
        ):
            raise ValueError("Bounded journal locator required")
        if source_event_id is not None:
            source_event_id = _uuid(source_event_id)
    before_digest = sha256(canonical(wire(before))).digest() if before is not None else None
    after_digest = sha256(canonical(wire(after))).digest() if after is not None else None
    payload = wire(
        {
            "alert_id": str(alert_id) if alert_id else None,
            "before_digest": before_digest.hex() if before_digest else None,
            "after_digest": after_digest.hex() if after_digest else None,
            "journal_order": journal_order,
            "source_event_id": str(source_event_id) if source_event_id else None,
            "projection_seq": projection_seq,
            "projection_version": projection_version,
            "disposition": disposition,
            "error_code": error_code,
        }
    )
    encoded = canonical(payload)
    fingerprint = sha256(encoded).digest()
    # Every mutation takes the coordinator before a seed/capacity row. A source
    # transaction may link several seeds; inconsistent ordering can deadlock it
    # against expansion holding a second seed while waiting for tenant capacity.
    coordinator(conn, tenant)
    seed = conn.execute(
        "SELECT id,allocations FROM visibility_inputs WHERE tenant_id=%s AND id=%s FOR UPDATE",
        (tenant, input_id),
    ).fetchone()
    if not seed:
        return {"status": "seed_unavailable"}
    limits = limits or InputLimits(**seed["allocations"])
    old = conn.execute(
        "SELECT fingerprint FROM visibility_applications WHERE tenant_id=%s AND input_id=%s AND id=%s",
        (tenant, input_id, application_id),
    ).fetchone()
    if old:
        if bytes(old["fingerprint"]) != fingerprint:
            raise AppError(
                "visibility_application_conflict", "Application identity has different proof.", 409
            )
        return {"status": "existing"}
    capacity = _capacity(conn, tenant)
    if (
        len(encoded) > limits.max_application_bytes
        or capacity["applications"] >= limits.max_tenant_applications
        or capacity["application_bytes"] + len(encoded) > limits.max_tenant_application_bytes
    ):
        conn.execute(
            "UPDATE visibility_inputs SET application_gap='application_allocation_exhausted' WHERE tenant_id=%s AND id=%s",
            (tenant, input_id),
        )
        return {"status": "capacity_gap"}
    conn.execute(
        """INSERT INTO visibility_applications(tenant_id,input_id,id,alert_id,before_digest,after_digest,
         projection_seq,projection_version,disposition,error_code,fingerprint,byte_charge,journal_order,source_event_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            tenant,
            input_id,
            application_id,
            alert_id,
            before_digest,
            after_digest,
            projection_seq,
            projection_version,
            disposition,
            error_code,
            fingerprint,
            len(encoded),
            journal_order,
            source_event_id,
        ),
    )
    conn.execute(
        "UPDATE visibility_input_capacity SET applications=applications+1,application_bytes=application_bytes+%s WHERE tenant_id=%s",
        (len(encoded), tenant),
    )
    # A previous gap stays visible: one successful link cannot prove all missing links.
    return {"status": "recorded"}


def _expand(conn, seed, limits):
    limits = limits or InputLimits(**seed["allocations"])
    tenant, input_id = seed["tenant_id"], seed["id"]
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    if seed["disposition"] != "pending" or seed["expansion_state"] == "expanded":
        return {
            "status": seed["expansion_state"],
            "input_id": input_id,
            "enumerated": 0,
            "selected": 0,
        }
    if seed["cohort_checkpoint"] is None or seed["started_at"] > now:
        return {"status": "boundary_unsealed", "input_id": input_id, "enumerated": 0, "selected": 0}
    comparator = "<" if seed["kind"] == "maintenance_expiry" else "<="
    bounds = f"tenant_id=%s AND checkpoint<=%s AND recorded_at{comparator}%s"
    args = [tenant, seed["cohort_checkpoint"], seed["started_at"]]
    keyset = " AND view_id>%s" if seed["last_view_id"] else ""
    views = conn.execute(
        "SELECT DISTINCT view_id FROM visibility_view_controls WHERE "
        + bounds
        + keyset
        + " ORDER BY view_id LIMIT %s",
        (*args, *([seed["last_view_id"]] if keyset else []), limits.max_views_per_turn + 1),
    ).fetchall()
    capacity = _capacity(conn, tenant)
    enumerated = chosen = 0
    position = seed["last_view_id"]
    gap = None
    for view in views[: limits.max_views_per_turn]:
        control = conn.execute(
            "SELECT checkpoint,snapshot FROM visibility_view_controls WHERE "
            + bounds
            + " AND view_id=%s ORDER BY recorded_at DESC,checkpoint DESC LIMIT 1",
            (*args, view["view_id"]),
        ).fetchone()
        snapshot = control["snapshot"]
        try:
            if not re.fullmatch(r"[1-9][0-9]*", snapshot["view_epoch"]):
                raise ValueError()
            epoch = int(snapshot["view_epoch"])
            state = snapshot["state"]
            lease_until = datetime.fromisoformat(snapshot["lease_until"])
            _time(lease_until)
            if (
                state not in {"foreground", "background", "closed"}
                or not isinstance(snapshot.get("deployment_epoch"), str)
                or not snapshot["deployment_epoch"]
                or snapshot.get("id") != str(view["view_id"])
                or snapshot.get("checkpoint") != str(control["checkpoint"])
                or not re.fullmatch(r"[0-9a-f]{64}", snapshot.get("query_digest", ""))
            ):
                raise ValueError()
            sampled = selected(
                input_id=input_id,
                view_id=view["view_id"],
                view_epoch=epoch,
                policy_epoch=seed["policy_epoch"],
                kind=seed["kind"],
                qualification=seed["qualification"],
            )
        except (KeyError, ValueError, TypeError):
            gap = "registry_proof_invalid"
            break
        if sampled:
            if capacity["candidates"] + chosen >= limits.max_tenant_candidates:
                gap = "candidate_allocation_exhausted"
                break
            reason = (
                "deployment_epoch_mismatch"
                if snapshot["deployment_epoch"] != seed["deployment_epoch"]
                else "reported_not_foreground"
                if state != "foreground"
                else "contact_unknown"
                if lease_until <= seed["started_at"]
                else "proof_pending"
            )
            conn.execute(
                """INSERT INTO visibility_candidates(tenant_id,input_id,view_id,view_epoch,control_checkpoint,query_digest,coverage_reason,deadline_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    tenant,
                    input_id,
                    view["view_id"],
                    epoch,
                    control["checkpoint"],
                    snapshot["query_digest"],
                    reason,
                    seed["deadline_at"],
                ),
            )
            chosen += 1
        enumerated += 1
        position = view["view_id"]
    complete = gap is None and len(views) <= limits.max_views_per_turn
    conn.execute(
        """UPDATE visibility_inputs SET last_view_id=%s,enumerated=enumerated+%s,selected=selected+%s,
         expansion_gap=%s,expansion_state=%s,expanded_at=%s,expansion_attempted_at=%s,
         deadline_exceeded=deadline_exceeded OR deadline_at<%s
         WHERE tenant_id=%s AND id=%s""",
        (
            position,
            enumerated,
            chosen,
            gap,
            "expanded" if complete else "pending",
            now if complete else None,
            now,
            now,
            tenant,
            input_id,
        ),
    )
    conn.execute(
        "UPDATE visibility_input_capacity SET candidates=candidates+%s WHERE tenant_id=%s",
        (chosen, tenant),
    )
    return {
        "status": "expanded" if complete else "pending",
        "input_id": input_id,
        "enumerated": enumerated,
        "selected": chosen,
        "gap": gap,
    }


def expand_input(conn, *, tenant, input_id, limits: InputLimits | None = None):
    coordinator(conn, tenant)
    seed = conn.execute(
        "SELECT * FROM visibility_inputs WHERE tenant_id=%s AND id=%s FOR UPDATE",
        (tenant, input_id),
    ).fetchone()
    if not seed:
        raise ValueError("Durable input seed required")
    return _expand(conn, seed, limits)


def expand_next(conn, *, limits: InputLimits | None = None, tenant=None):
    """One atomic bounded worker turn. Row locks expire on crash; no lost leases."""
    query = """SELECT i.tenant_id,i.id FROM visibility_inputs i
        JOIN tenant_work_state w ON w.tenant_id=i.tenant_id
        WHERE i.expansion_state='pending' AND i.disposition='pending'
        AND i.cohort_checkpoint IS NOT NULL AND i.started_at<=clock_timestamp()"""
    if tenant is not None:
        query += " AND i.tenant_id=%s"
    seed = conn.execute(
        query
        + " ORDER BY i.expansion_attempted_at NULLS FIRST,i.started_at,i.tenant_id,i.id LIMIT 1 FOR UPDATE OF w SKIP LOCKED",
        (tenant,) if tenant is not None else (),
    ).fetchone()
    # Lock only the coordinator at selection, skipping busy tenants. Recheck the
    # seed after that lock; never hold a seed while waiting for its coordinator.
    return (
        expand_input(conn, tenant=seed["tenant_id"], input_id=seed["id"], limits=limits)
        if seed
        else None
    )


def coverage(conn, tenant):
    """Operational gap inventory, never an eligible denominator or success rate."""
    counts = conn.execute(
        """SELECT count(*) AS seeds,count(*) FILTER(WHERE disposition='pending' AND expansion_state='pending') AS pending,
        count(*) FILTER(WHERE disposition='pending' AND deadline_at<clock_timestamp()) AS overdue_unclassified,
        count(*) FILTER(WHERE disposition='pending' AND cohort_checkpoint IS NULL) AS unsealed,
        coalesce(sum(enumerated),0) AS enumerated,coalesce(sum(selected),0) AS selected
        FROM visibility_inputs WHERE tenant_id=%s""",
        (tenant,),
    ).fetchone()
    capacity = conn.execute(
        "SELECT seed_gap_attempts FROM visibility_input_capacity WHERE tenant_id=%s", (tenant,)
    ).fetchone()
    return {
        **counts,
        "seed_gap_attempts": capacity["seed_gap_attempts"] if capacity else 0,
        "eligibility": "unclassified",
        "render_proof": "unavailable",
    }
