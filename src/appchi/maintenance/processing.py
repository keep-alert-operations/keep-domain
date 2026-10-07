"""Complete-proof SQL adapter. The caller owns coordinator/aggregate locks.

Compile catalogs before taking write locks. Journal every source receipt, even a
repeat, and every semantic rule-field transition. Existing snapshots without a
creation baseline are deliberately not accepted as reconstructed history.
"""

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import hashlib
from uuid import UUID, uuid5

from psycopg.types.json import Jsonb

from appchi.cel import compile_expression
from appchi.cel.catalog import RULE_FIELDS
from appchi.ingestion.native import canonical
from appchi.shared.errors import unavailable
from appchi.shared.transactions import coordinator
from appchi.serialization import wire

from .temporal import AlertTransition, Boundary, MaintenanceProofError, Segment, reduce_alert


@dataclass(frozen=True)
class Catalog:
    tenant_id: UUID
    generation: int
    segments: tuple[Segment, ...]
    max_work: int
    max_inputs: int
    inline_correlation: object | None = None
    inline_requested: bool = False
    source_release_since: datetime | None = None
    history_complete: bool = True
    replays: object | None = None
    require_preparation: bool = False


@dataclass(frozen=True)
class Effects:
    suppression_changed: bool
    history_changed: bool
    qualifiers: tuple[tuple[UUID, datetime], ...]
    withdrawn_qualifiers: tuple[UUID, ...]
    proof_digest: bytes
    input_suppressed: bool | None = None


@dataclass(frozen=True)
class HistoricalSuppression:
    before: bool
    after: bool
    catalog_generation: int
    checkpoint_digest: bytes
    input_revision: int


def suppression_at(conn, tenant_id, alert_id, effective_at, original_order):
    """Historical before/after suppression from a current complete checkpoint.

    The decision caller must hold coordinator/aggregate/alert locks and call
    reconcile_alert with the current precompiled catalog first. No global fanout
    completion is needed: this one alert must have complete current proof.
    """
    row = conn.execute(
        """SELECT c.*,v.maintenance_generation,h.input_revision AS head_revision FROM maintenance_alert_checkpoints c
        JOIN tenant_view_state v ON v.tenant_id=c.tenant_id JOIN maintenance_alert_input_heads h ON h.tenant_id=c.tenant_id AND h.alert_id=c.alert_id WHERE c.tenant_id=%s AND c.alert_id=%s""",
        (tenant_id, alert_id),
    ).fetchone()
    if not row or not row["complete"] or row["input_revision"] != row["head_revision"]:
        raise MaintenanceProofError("maintenance_historical_checkpoint_unproven")
    if type(original_order) is not int or original_order < 1 or effective_at.tzinfo is None:
        raise MaintenanceProofError("maintenance_historical_boundary_invalid")
    result = []
    for after in (False, True):
        opened = "<=" if after else "<"
        closed = ">" if after else ">="
        maintenance = conn.execute(
            f"""SELECT 1 FROM alert_maintenance_causes WHERE tenant_id=%s AND alert_id=%s
            AND (opened_at,opened_order) {opened} (%s,%s)
            AND (closed_at IS NULL OR (closed_at,closed_order) {closed} (%s,%s)) LIMIT 1""",
            (tenant_id, alert_id, effective_at, original_order, effective_at, original_order),
        ).fetchone()
        source = conn.execute(
            f"""SELECT source_suppressed FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s
            AND source_suppressed IS NOT NULL AND original_order {opened} %s
            ORDER BY original_order DESC LIMIT 1""",
            (tenant_id, alert_id, original_order),
        ).fetchone()
        result.append(bool(maintenance or (source and source["source_suppressed"])))
    return HistoricalSuppression(
        result[0], result[1], row["catalog_generation"], row["proof_digest"], row["input_revision"]
    )


def prepare_catalog(
    database,
    tenant_id,
    *,
    max_work,
    max_inputs,
    max_segments,
    alert_id=None,
    effective_at=None,
    alert_ids=(),
):
    """Bounded DB snapshot followed by native CEL compilation outside locks."""
    if min(max_work, max_inputs, max_segments) < 1:
        raise ValueError("explicit positive qualified work allocations are required")
    with database.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SELECT set_config('appchi.tenant_id',%s,true)", (str(tenant_id),))
        state = conn.execute(
            "SELECT maintenance_generation,clock_timestamp() AS prepared_at,(SELECT source_release_since FROM application_scope WHERE singleton) AS source_release_since FROM tenant_view_state WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
        targets = tuple(
            dict.fromkeys(
                [str(value) for value in alert_ids] + ([str(alert_id)] if alert_id else [])
            )
        )
        previous = (
            conn.execute(
                "SELECT continuation FROM maintenance_alert_checkpoints WHERE tenant_id=%s AND alert_id=ANY(%s::uuid[])",
                (tenant_id, list(targets)),
            ).fetchall()
            if targets
            else []
        )
        continuations = [row["continuation"] for row in previous]
        at = effective_at or state["prepared_at"]
        floor = None
        active_ids = []
        if (
            targets
            and len(continuations) == len(targets)
            and all(
                continuation
                and continuation.get("version") in (1, "1", 2, "2")
                and int(continuation["generation"]) == state["maintenance_generation"]
                and at > datetime.fromisoformat(continuation.get("max_at", continuation["last_at"]))
                for continuation in continuations
            )
        ):
            floor = min(
                datetime.fromisoformat(continuation.get("max_at", continuation["last_at"]))
                for continuation in continuations
            )
            active_ids = list(
                {
                    cause["segment_id"]
                    for continuation in continuations
                    for cause in continuation["causes"]
                    if cause["segment_id"]
                }
            )
        elif not targets and effective_at is not None:
            # An explicitly identified new alert has no preceding causes.
            floor = effective_at
        rows = conn.execute(
            """SELECT * FROM maintenance_segments WHERE tenant_id=%s
            AND (%s::timestamptz IS NULL
              OR LEAST(end_at,COALESCE(deactivation_at,end_at))>=%s OR id=ANY(%s::uuid[]))
            ORDER BY activation_at,activation_order,id""",
            (tenant_id, floor, floor, active_ids),
        ).fetchall()
    active_count = sum(
        row["start_at"] <= at < row["end_at"]
        and row["activation_at"] < at
        and row["deactivation_id"] is None
        for row in rows
    )
    if not state or active_count > max_segments:
        raise unavailable("maintenance_catalog_allocation_exceeded")
    programs, segments = {}, []
    for row in rows:
        key = (row["cel"], row["profile"], row["cel_digest"])
        if key not in programs:
            program = compile_expression(row["cel"], rule=True)
            if (
                program.profile != row["profile"]
                or hashlib.sha256(row["cel"].encode()).hexdigest() != row["cel_digest"]
            ):
                raise unavailable("maintenance_profile_mismatch")
            programs[key] = program
        segments.append(
            Segment(
                row["id"],
                row["window_id"],
                row["expression_revision"],
                Boundary(row["activation_at"], row["activation_order"], str(row["activation_id"])),
                row["start_at"],
                row["end_at"],
                programs[key],
                Boundary(
                    row["deactivation_at"], row["deactivation_order"], str(row["deactivation_id"])
                )
                if row["deactivation_id"]
                else None,
                tuple(
                    (
                        Boundary(datetime.fromisoformat(v["at"]), int(v["order"]), v["id"]),
                        datetime.fromisoformat(v["end"]),
                    )
                    for v in row["end_revisions"]
                ),
            )
        )
    return Catalog(
        UUID(str(tenant_id)),
        state["maintenance_generation"],
        tuple(segments),
        max_work,
        max_inputs,
        source_release_since=state["source_release_since"],
        history_complete=floor is None,
    )


def _snapshot(value):
    if value is None:
        return None
    if not RULE_FIELDS.issubset(value):
        raise MaintenanceProofError("maintenance_rule_snapshot_incomplete")
    snapshot = {key: value[key] for key in sorted(RULE_FIELDS)}
    created = snapshot["time_created"]
    if isinstance(created, str):
        try:
            created = datetime.fromisoformat(created)
        except ValueError:
            raise MaintenanceProofError("maintenance_rule_timestamp_invalid") from None
    if not isinstance(created, datetime) or created.tzinfo is None:
        raise MaintenanceProofError("maintenance_rule_timestamp_invalid")
    snapshot["time_created"] = created.astimezone(UTC)
    return wire(snapshot)


def _check_catalog(conn, tenant_id, catalog):
    if UUID(str(tenant_id)) != catalog.tenant_id:
        raise MaintenanceProofError("maintenance_catalog_tenant_mismatch")
    row = conn.execute(
        "SELECT maintenance_generation FROM tenant_view_state WHERE tenant_id=%s", (tenant_id,)
    ).fetchone()
    if not row or row["maintenance_generation"] != catalog.generation:
        raise unavailable("maintenance_catalog_changed")


def record_transition(
    conn, before, after, effective_time, original_order, cause, processing_now, *, catalog
):
    """Return (adjusted current snapshot, Effects), writing proof atomically.

    The caller must already hold tenant coordinator, incident/context locks then
    alert lock. A new alert identity must exist. These functions do not publish
    alerts or change semantic/projection revisions: the caller incorporates the
    returned change into its single semantic transition and publication.
    """
    _check_catalog(conn, after["tenant_id"], catalog)
    record_input(conn, before, after, effective_time, original_order, cause, processing_now)
    adjusted, effects = reconcile_alert(conn, after, processing_now, catalog=catalog)
    historical = conn.execute(
        """SELECT 1 FROM alert_maintenance_causes WHERE tenant_id=%s AND alert_id=%s
        AND (opened_at<%s OR (opened_at=%s AND opened_order<=%s))
        AND (closed_at IS NULL OR closed_at>%s OR (closed_at=%s AND closed_order>%s)) LIMIT 1""",
        (
            after["tenant_id"],
            after["id"],
            effective_time,
            effective_time,
            original_order,
            effective_time,
            effective_time,
            original_order,
        ),
    ).fetchone()
    return adjusted, replace(
        effects, input_suppressed=bool(after.get("source_suppressed") or historical)
    )


def record_input(conn, before, after, effective_time, original_order, cause, processing_now):
    """Persist every source and semantic transition, even while maintenance is gated.

    No catalog/evaluation or inferred baseline. Replay compares the full input
    fingerprint, ignoring derived suppression and publication revisions. Caller
    already owns coordinator and alert locks and the alert identity exists.
    """
    tenant, alert_id = after["tenant_id"], UUID(str(after["id"]))
    if (
        not isinstance(original_order, int)
        or isinstance(original_order, bool)
        or original_order < 1
    ):
        raise MaintenanceProofError("maintenance_original_order_required")
    if (
        effective_time.tzinfo is None
        or processing_now.tzinfo is None
        or effective_time > processing_now
    ):
        raise MaintenanceProofError("maintenance_effective_time_invalid")
    if before is not None and (
        str(before["id"]) != str(alert_id) or str(before["tenant_id"]) != str(tenant)
    ):
        raise MaintenanceProofError("maintenance_before_identity_mismatch")
    previous, current = _snapshot(before), _snapshot(after)
    source = after.get("source_suppressed", False) if cause == "source" else None
    if source is not None and not isinstance(source, bool):
        raise MaintenanceProofError("maintenance_source_flag_invalid")
    identity = uuid5(
        alert_id, f"input:{effective_time.astimezone(UTC).isoformat()}:{original_order}"
    )
    proof = {"before": previous, "after": current, "cause": cause, "source_suppressed": source}
    digest = hashlib.sha256(canonical(proof)).digest()
    inserted = conn.execute(
        """INSERT INTO maintenance_alert_inputs(tenant_id,alert_id,id,effective_at,original_order,kind,new_logical_alert,before_snapshot,after_snapshot,source_suppressed,request_digest,recorded_at)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,alert_id,id) DO NOTHING RETURNING id""",
        (
            tenant,
            alert_id,
            identity,
            effective_time,
            original_order,
            cause,
            before is None,
            Jsonb(previous) if previous is not None else None,
            Jsonb(current),
            source,
            digest,
            processing_now,
        ),
    ).fetchone()
    stored = conn.execute(
        "SELECT request_digest FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s AND id=%s",
        (tenant, alert_id, identity),
    ).fetchone()
    if stored["request_digest"] != digest:
        raise MaintenanceProofError("maintenance_conflicting_input_replay")
    if inserted:
        conn.execute(
            """INSERT INTO maintenance_alert_input_heads(tenant_id,alert_id,input_revision,last_input_id) VALUES(%s,%s,1,%s)
            ON CONFLICT(tenant_id,alert_id) DO UPDATE SET input_revision=maintenance_alert_input_heads.input_revision+1,last_input_id=EXCLUDED.last_input_id""",
            (tenant, alert_id, identity),
        )
        conn.execute(
            "UPDATE maintenance_alert_checkpoints SET complete=false WHERE tenant_id=%s AND alert_id=%s",
            (tenant, alert_id),
        )
    return identity, digest


def reconcile_alert(conn, current, processing_now, *, catalog):
    """Replay full retained proof, including controls committed after sources.

    A fanout caller must first drain earlier admitted source work for this alert
    and preserve aggregate lock order. No new source input is invented here.
    """
    tenant, alert_id = current["tenant_id"], UUID(str(current["id"]))
    _check_catalog(conn, tenant, catalog)
    prior = conn.execute(
        "SELECT * FROM maintenance_alert_checkpoints WHERE tenant_id=%s AND alert_id=%s FOR UPDATE",
        (tenant, alert_id),
    ).fetchone()
    head = conn.execute(
        "SELECT input_revision,last_input_id FROM maintenance_alert_input_heads WHERE tenant_id=%s AND alert_id=%s",
        (tenant, alert_id),
    ).fetchone()
    from .incremental import advance, checkpoint

    continuation = prior and prior.get("continuation")
    incremental = False
    result = None
    rows = []
    prepared = (catalog.replays or {}).get(alert_id)
    if (
        prepared is not None
        and not prepared.predicted
        and head
        and head["input_revision"] > prepared.input_revision
        and head["input_revision"] <= catalog.max_inputs
        and catalog.history_complete
        and catalog.source_release_since is not None
        and processing_now < catalog.source_release_since
    ):
        # Retained pre-cutover commands use timer-release semantics, which a
        # post-cutover continuation intentionally cannot advance. Recompute this
        # small legacy timeline exactly from locked SQL authority; do not reject
        # a valid command merely because its baseline was prepared off-lock.
        # Large timelines and all current post-cutover work still require the
        # normal fenced preparation/continuation path.
        prepared = None
    prepared_history = None
    if prepared is not None:
        latest = (
            conn.execute(
                "SELECT * FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s AND id=%s",
                (tenant, alert_id, head["last_input_id"]),
            ).fetchone()
            if head
            else None
        )
        if (
            prepared.predicted
            and head
            and head["input_revision"] == prepared.input_revision
            and latest
        ):
            from .preparation import bind_source

            prepared = bind_source(prepared, latest, alert_id)
        if (
            head
            and head["input_revision"] == prepared.input_revision
            and head["last_input_id"] == prepared.last_id
            and latest
            and bytes(latest["request_digest"]) == prepared.last_digest
        ):
            result, continuation = prepared.result, prepared.continuation
        elif (
            head
            and not prepared.predicted
            and latest
            and head["input_revision"] == prepared.input_revision + 1
        ):
            baseline_intervals = prepared.history_intervals[-1:]
            advanced = advance(
                alert_id,
                prepared.continuation,
                baseline_intervals,
                AlertTransition(
                    Boundary(latest["effective_at"], latest["original_order"], str(latest["id"])),
                    latest["before_snapshot"],
                    latest["after_snapshot"],
                    latest["new_logical_alert"],
                    latest["source_suppressed"],
                    latest["kind"],
                ),
                catalog.segments,
                now=processing_now,
                generation=catalog.generation,
                source_release_since=catalog.source_release_since,
                max_work=catalog.max_work,
            )
            if advanced is None:
                raise unavailable("maintenance_preparation_changed")
            result, continuation = advanced
            causes = {cause.id: cause for cause in prepared.result.causes}
            causes.update({cause.id: cause for cause in result.causes})
            proofs = {item[0]: item for item in prepared.result.qualifier_inputs}
            proofs.update({item[0]: item for item in result.qualifier_inputs})
            result = replace(
                result,
                causes=tuple(causes.values()),
                final_unsuppression_qualifiers=tuple(proofs),
                qualifier_inputs=tuple(proofs.values()),
            )
            rows = [latest]
        else:
            raise unavailable("maintenance_preparation_changed")
        if result.final_snapshot != _snapshot(current):
            raise unavailable("maintenance_preparation_changed")
        prepared_history = list(prepared.history_intervals)
        tail = wire([{"start": item.start, "end": item.end} for item in result.effective_intervals])
        if tail and prepared_history and tail[0]["start"] == prepared_history[-1]["start"]:
            prepared_history[-1:] = tail
        elif tail:
            prepared_history.extend(tail)
        incremental = True
    if (
        not incremental
        and continuation
        and continuation.get("version") in (1, "1", 2, "2")
        and int(continuation["generation"]) == catalog.generation
    ):
        rows = conn.execute(
            """SELECT * FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s
            AND original_order>%s ORDER BY original_order LIMIT %s""",
            (tenant, alert_id, continuation["last_order"], catalog.max_inputs + 1),
        ).fetchall()
        if not rows and head and prior["input_revision"] == head["input_revision"]:
            if continuation["snapshot"] != _snapshot(current):
                raise MaintenanceProofError("maintenance_current_snapshot_unproven")
            return dict(current, suppressed=prior["current_suppressed"]), Effects(
                bool(current.get("suppressed")) != prior["current_suppressed"],
                False,
                (),
                (),
                bytes(prior["proof_digest"]),
            )
        if len(rows) == 1 and head and head["input_revision"] == prior["input_revision"] + 1:
            row = rows[0]
            advanced = advance(
                alert_id,
                continuation,
                prior["union_intervals"],
                AlertTransition(
                    Boundary(row["effective_at"], row["original_order"], str(row["id"])),
                    row["before_snapshot"],
                    row["after_snapshot"],
                    row["new_logical_alert"],
                    row["source_suppressed"],
                    row["kind"],
                ),
                catalog.segments,
                now=processing_now,
                generation=catalog.generation,
                source_release_since=catalog.source_release_since,
                max_work=catalog.max_work,
            )
            if advanced is not None:
                result, continuation = advanced
                incremental = True
    if not incremental:
        if not catalog.history_complete and prior is not None:
            # A concurrent source changed the prepared predecessor. Retry
            # preparation outside write locks, with the now-current checkpoint.
            raise unavailable("maintenance_catalog_changed")
        if catalog.require_preparation and head and head["input_revision"] > catalog.max_inputs:
            # Live callers prepare a fenced historical result before acquiring
            # writer locks. A stale/missing preparation retains the operation
            # for retry; this is not a maximum lifetime accepted-input count.
            raise unavailable("maintenance_preparation_required")
        rows = []
        position = 0
        while True:
            page = conn.execute(
                """SELECT * FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s
                AND original_order>%s ORDER BY original_order LIMIT %s""",
                (tenant, alert_id, position, catalog.max_inputs),
            ).fetchall()
            rows.extend(page)
            if len(page) < catalog.max_inputs:
                break
            position = page[-1]["original_order"]
    if rows and not incremental and (not head or head["input_revision"] != len(rows)):
        raise MaintenanceProofError("maintenance_input_head_mismatch")
    transitions = tuple(
        AlertTransition(
            Boundary(row["effective_at"], row["original_order"], str(row["id"])),
            row["before_snapshot"],
            row["after_snapshot"],
            row["new_logical_alert"],
            row["source_suppressed"],
            row["kind"],
        )
        for row in rows
    )
    result = result or reduce_alert(
        alert_id,
        catalog.segments,
        transitions,
        now=processing_now,
        recorded_at=processing_now,
        proof_complete=bool(rows and rows[0]["new_logical_alert"]),
        max_work=catalog.max_work,
        source_release_since=catalog.source_release_since,
        per_input_budget=True,
    )
    if result.final_snapshot != _snapshot(current):
        raise MaintenanceProofError("maintenance_current_snapshot_unproven")
    if not incremental:
        continuation = checkpoint(
            result,
            rows[-1],
            generation=catalog.generation,
            source_release_since=catalog.source_release_since,
            max_at=max(row["effective_at"] for row in rows),
        )
    intervals = wire(
        [{"start": interval.start, "end": interval.end} for interval in result.effective_intervals]
    )
    evidence = {
        "inputs": [row["request_digest"].hex() for row in rows],
        "generation": catalog.generation,
        "causes": [
            wire(
                {
                    "id": item.id,
                    "opened": item.opened.at,
                    "opening": item.opened.id,
                    "closed": item.closed.at if item.closed else None,
                    "closing": item.closed.id if item.closed else None,
                }
            )
            for item in result.causes
        ],
    }
    if incremental:
        evidence["predecessor"] = (
            prepared.digest if prepared is not None else bytes(prior["proof_digest"])
        ).hex()
    digest = hashlib.sha256(canonical(evidence)).digest()
    changed = False
    for item in result.causes:
        if item.window_id is not None:
            conn.execute(
                """INSERT INTO alert_maintenance_causes(tenant_id,alert_id,id,window_id,segment_id,opening_proof,opened_at,opened_order,closed_at,closed_order,closing_proof,recorded_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,alert_id,id) DO UPDATE SET closed_at=EXCLUDED.closed_at,closed_order=EXCLUDED.closed_order,closing_proof=EXCLUDED.closing_proof""",
                (
                    tenant,
                    alert_id,
                    item.id,
                    item.window_id,
                    item.segment_id,
                    item.opened.id,
                    item.opened.at,
                    item.opened.order,
                    item.closed.at if item.closed else None,
                    item.closed.order if item.closed else None,
                    item.closed.id if item.closed else None,
                    processing_now,
                ),
            )
        for kind, boundary in (("open", item.opened), ("close", item.closed)):
            if boundary is None:
                continue
            event_id = uuid5(item.id, kind + ":" + boundary.id)
            correction = conn.execute(
                "SELECT id FROM maintenance_cause_history WHERE tenant_id=%s AND alert_id=%s AND cause_id=%s AND boundary_kind=%s AND evidence->>'interval_id'=%s ORDER BY recorded_at DESC,id DESC LIMIT 1",
                (tenant, alert_id, item.cause_id, kind, str(item.id)),
            ).fetchone()
            inserted = conn.execute(
                """INSERT INTO maintenance_cause_history(tenant_id,alert_id,id,cause_id,boundary_kind,boundary_id,effective_at,recorded_at,evidence,corrects_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING id""",
                (
                    tenant,
                    alert_id,
                    event_id,
                    item.cause_id,
                    kind,
                    boundary.id,
                    boundary.at,
                    processing_now,
                    Jsonb(
                        wire(
                            {
                                "interval_id": item.id,
                                "window_id": item.window_id,
                                "segment_id": item.segment_id,
                                "order": boundary.order,
                            }
                        )
                    ),
                    correction["id"] if correction and correction["id"] != event_id else None,
                ),
            ).fetchone()
            changed = changed or inserted is not None
    if (
        prior is None
        or prior["union_intervals"] != intervals
        or prepared is not None
        and (prepared.result.causes or prepared.withdrawn)
    ):
        previous_union = conn.execute(
            "SELECT id FROM maintenance_union_history WHERE tenant_id=%s AND alert_id=%s ORDER BY recorded_at DESC,id DESC LIMIT 1",
            (tenant, alert_id),
        ).fetchone()
        conn.execute(
            "INSERT INTO maintenance_union_history(tenant_id,alert_id,id,proof_digest,effective_intervals,recorded_at,corrects_id,representation) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (
                tenant,
                alert_id,
                uuid5(alert_id, "union:" + digest.hex()),
                digest,
                Jsonb(prepared_history if prepared_history is not None else intervals),
                processing_now,
                previous_union["id"] if previous_union else None,
                "tail" if incremental and prepared is None else "full",
            ),
        )
    qualifiers = {
        uuid5(alert_id, "final-unsuppression:" + at.isoformat()): at
        for at in result.final_unsuppression_qualifiers
    }
    previous_qualifiers = {
        row["id"]: row
        for row in conn.execute(
            """SELECT * FROM maintenance_qualifier_effects WHERE tenant_id=%s AND alert_id=%s
            AND (%s OR id=ANY(%s::uuid[]))""",
            (
                tenant,
                alert_id,
                not incremental,
                list(
                    set(qualifiers) | (set(prepared.withdrawn) if prepared is not None else set())
                ),
            ),
        ).fetchall()
    }
    new = []
    qualifier_proofs = {
        at: (source_id, allowed, origin_id)
        for at, source_id, allowed, origin_id in result.qualifier_inputs
    }
    for identity, at in qualifiers.items():
        previous = previous_qualifiers.get(identity)
        proof = qualifier_proofs[at]
        previous_proof = (
            None
            if previous is None
            else (
                str(previous["source_input_id"]),
                previous["correlation_allowed"],
                str(previous["origin_input_id"]) if previous["origin_input_id"] else None,
            )
        )
        if previous is None or not previous["active"] or previous_proof != proof:
            # A delayed applied source can change the snapshot/provenance of an
            # already-known end instant. Retract its old evidence atomically.
            conn.execute(
                "DELETE FROM correlation_evidence WHERE tenant_id=%s AND alert_id=%s AND qualifier_ref=%s",
                (tenant, alert_id, identity),
            )
            conn.execute(
                "INSERT INTO maintenance_qualifier_effects(tenant_id,alert_id,id,effective_at,active,recorded_at,source_input_id,correlation_allowed,origin_input_id) VALUES(%s,%s,%s,%s,true,%s,%s,%s,%s) ON CONFLICT(tenant_id,alert_id,id) DO UPDATE SET active=true,recorded_at=EXCLUDED.recorded_at,source_input_id=EXCLUDED.source_input_id,correlation_allowed=EXCLUDED.correlation_allowed,origin_input_id=EXCLUDED.origin_input_id",
                (tenant, alert_id, identity, at, processing_now, *proof),
            )
            new.append((identity, at))
    withdrawn = tuple(
        identity
        for identity, row in previous_qualifiers.items()
        if row["active"] and identity not in qualifiers
    )
    for identity in withdrawn:
        conn.execute(
            "UPDATE maintenance_qualifier_effects SET active=false,recorded_at=%s WHERE tenant_id=%s AND alert_id=%s AND id=%s",
            (processing_now, tenant, alert_id, identity),
        )
    suppressed = bool(result.current_causes)
    conn.execute(
        """INSERT INTO maintenance_alert_checkpoints(tenant_id,alert_id,proof_digest,catalog_generation,current_suppressed,current_cause_ids,union_intervals,complete,checked_at,input_revision,continuation)
        VALUES(%s,%s,%s,%s,%s,%s,%s,true,%s,%s,%s) ON CONFLICT(tenant_id,alert_id) DO UPDATE SET proof_digest=EXCLUDED.proof_digest,catalog_generation=EXCLUDED.catalog_generation,current_suppressed=EXCLUDED.current_suppressed,current_cause_ids=EXCLUDED.current_cause_ids,union_intervals=EXCLUDED.union_intervals,complete=true,checked_at=EXCLUDED.checked_at,input_revision=EXCLUDED.input_revision,continuation=EXCLUDED.continuation""",
        (
            tenant,
            alert_id,
            digest,
            catalog.generation,
            suppressed,
            Jsonb(list(result.current_causes)),
            Jsonb(intervals[-1:]),
            processing_now,
            head["input_revision"],
            Jsonb(continuation),
        ),
    )
    adjusted = dict(current, suppressed=suppressed)
    return adjusted, Effects(
        bool(current.get("suppressed")) != suppressed, changed, tuple(new), withdrawn, digest
    )


@dataclass(frozen=True)
class Lease:
    tenant_id: UUID
    job_id: UUID
    generation: int


def claim_due(database, tenant_id):
    """Claim one durable job. The host invokes this on its one-second scan.

    A scheduled end publishes its invalidation exactly once, at the original
    end instant. Call prepare_catalog AFTER this function: the generation may
    have advanced. Ten-second leases fence crashes and competing workers.
    """
    with database.transaction(tenant_id) as conn:
        _, now = coordinator(conn, tenant_id)
        candidate = conn.execute(
            """SELECT * FROM maintenance_fanout_jobs WHERE tenant_id=%s AND state='pending'
            AND due_at<=%s AND (lease_until IS NULL OR lease_until<=%s) ORDER BY due_at,id LIMIT 1""",
            (tenant_id, now, now),
        ).fetchone()
        if not candidate:
            return None
        window = conn.execute(
            "SELECT * FROM maintenance_windows WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant_id, candidate["window_id"]),
        ).fetchone()
        job = conn.execute(
            "SELECT * FROM maintenance_fanout_jobs WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant_id, candidate["id"]),
        ).fetchone()
        if not window:
            raise MaintenanceProofError("maintenance_window_proof_missing")
        if job["kind"] == "scheduled_end":
            segment = conn.execute(
                "SELECT * FROM maintenance_segments WHERE tenant_id=%s AND id=%s",
                (tenant_id, job["segment_id"]),
            ).fetchone()
            if (
                not segment
                or segment["deactivation_id"]
                or segment["end_at"] != job["expected_end"]
            ):
                conn.execute(
                    "UPDATE maintenance_fanout_jobs SET state='obsolete' WHERE id=%s", (job["id"],)
                )
                return None
            boundary_id = uuid5(job["id"], "scheduled-end")
            existing = conn.execute(
                "SELECT 1 FROM maintenance_controls WHERE tenant_id=%s AND id=%s",
                (tenant_id, boundary_id),
            ).fetchone()
            if not existing:
                order = conn.execute(
                    "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
                    (tenant_id,),
                ).fetchone()["admission_order"]
                generation = conn.execute(
                    "UPDATE tenant_view_state SET maintenance_generation=maintenance_generation+1,view_generation=view_generation+1 WHERE tenant_id=%s RETURNING maintenance_generation",
                    (tenant_id,),
                ).fetchone()["maintenance_generation"]
                conn.execute(
                    "INSERT INTO maintenance_controls(id,tenant_id,window_id,revision,effective_at,tenant_order,kind,generation) VALUES(%s,%s,%s,%s,%s,%s,'scheduled_end',%s)",
                    (
                        boundary_id,
                        tenant_id,
                        window["id"],
                        window["revision"],
                        job["expected_end"],
                        order,
                        generation,
                    ),
                )
                conn.execute(
                    "UPDATE maintenance_fanout_jobs SET generation=%s WHERE id=%s",
                    (generation, job["id"]),
                )
        row = conn.execute(
            "UPDATE maintenance_fanout_jobs SET lease_generation=lease_generation+1,lease_until=%s WHERE id=%s RETURNING lease_generation",
            (now + timedelta(seconds=10), job["id"]),
        ).fetchone()
        conn.execute(
            "UPDATE maintenance_windows SET processing_health='updating' WHERE tenant_id=%s AND id=%s",
            (tenant_id, window["id"]),
        )
        return Lease(UUID(str(tenant_id)), job["id"], row["lease_generation"])


def step_job(database, lease, catalog, *, lock_alert, publish):
    """Process at most ONE complete alert per transaction, returning status.

    lock_alert(conn, tenant, alert_id) must lock contexts/incidents BEFORE the
    alert, reject pending earlier source work, and return current retained state.
    publish(conn, before, adjusted, effects, now) must atomically store revisions,
    aggregate changes, all correlation effects and projection/live outboxes.
    Mandatory callbacks make unintegrated publication impossible to overlook.

    The host yields after 100 alerts or 100 ms between these complete steps, and
    must call again within three seconds while holding a lease. Every step
    renews the ten-second lease. No network calls belong inside either callback.
    """
    with database.transaction(lease.tenant_id) as conn:
        _, now = coordinator(conn, lease.tenant_id)
        conn.execute(
            "SELECT id FROM maintenance_windows WHERE tenant_id=%s AND id=ANY(%s::uuid[]) ORDER BY id FOR UPDATE",
            (lease.tenant_id, sorted({str(segment.window_id) for segment in catalog.segments})),
        ).fetchall()
        hint = conn.execute(
            "SELECT window_id FROM maintenance_fanout_jobs WHERE tenant_id=%s AND id=%s",
            (lease.tenant_id, lease.job_id),
        ).fetchone()
        if not hint:
            raise MaintenanceProofError("maintenance_job_missing")
        conn.execute(
            "SELECT id FROM maintenance_windows WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (lease.tenant_id, hint["window_id"]),
        )
        job = conn.execute(
            "SELECT * FROM maintenance_fanout_jobs WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (lease.tenant_id, lease.job_id),
        ).fetchone()
        if (
            job["state"] != "pending"
            or job["lease_generation"] != lease.generation
            or not job["lease_until"]
            or job["lease_until"] <= now
        ):
            return "stale"
        _check_catalog(conn, lease.tenant_id, catalog)
        row = conn.execute(
            """SELECT DISTINCT alert_id FROM alert_maintenance_causes WHERE tenant_id=%s AND window_id=%s
            AND (%s::uuid IS NULL OR segment_id=%s) AND (%s::uuid IS NULL OR alert_id>%s)
            ORDER BY alert_id LIMIT 1""",
            (
                lease.tenant_id,
                job["window_id"],
                job["segment_id"],
                job["segment_id"],
                job["cursor_alert_id"],
                job["cursor_alert_id"],
            ),
        ).fetchone()
        if not row:
            sequence = conn.execute(
                "SELECT projection_seq FROM tenant_work_state WHERE tenant_id=%s",
                (lease.tenant_id,),
            ).fetchone()["projection_seq"]
            conn.execute(
                "UPDATE maintenance_fanout_jobs SET state='complete',lease_until=NULL,required_projection_seq=%s WHERE id=%s",
                (sequence, job["id"]),
            )
            other = conn.execute(
                "SELECT 1 FROM maintenance_fanout_jobs WHERE tenant_id=%s AND window_id=%s AND state IN ('pending','blocked') AND due_at<=%s LIMIT 1",
                (lease.tenant_id, job["window_id"], now),
            ).fetchone()
            if not other:
                conn.execute(
                    "UPDATE maintenance_windows SET processing_health='healthy' WHERE tenant_id=%s AND id=%s",
                    (lease.tenant_id, job["window_id"]),
                )
            return "complete"
        before = lock_alert(conn, lease.tenant_id, row["alert_id"])
        if before is None:
            raise MaintenanceProofError("maintenance_retained_alert_missing")
        after, effects = reconcile_alert(conn, before, now, catalog=catalog)
        # A previous transaction can have materialized an end while its source
        # proof was awaiting Kafka. The callback must also see unchanged proof.
        publish(conn, before, after, effects, now)
        from appchi.visibility.runtime import link_expiry_result

        link_expiry_result(
            conn,
            job,
            before=before,
            after=after,
            changed=effects.suppression_changed or effects.history_changed,
        )
        conn.execute(
            "UPDATE maintenance_fanout_jobs SET cursor_alert_id=%s,lease_until=%s WHERE id=%s AND lease_generation=%s",
            (row["alert_id"], now + timedelta(seconds=10), job["id"], lease.generation),
        )
        return "processed"


def finish_failed_job(database, lease, *, proof_blocked):
    """Fence a failed attempt after its work transaction rolled back.

    Proof/CEL failures require repair; temporary source-pending or catalog
    conflicts release only this lease for a subsequent scan. Never clear causes.
    """
    with database.transaction(lease.tenant_id) as conn:
        coordinator(conn, lease.tenant_id)
        row = conn.execute(
            "SELECT window_id FROM maintenance_fanout_jobs WHERE tenant_id=%s AND id=%s",
            (lease.tenant_id, lease.job_id),
        ).fetchone()
        if not row:
            return False
        conn.execute(
            "SELECT id FROM maintenance_windows WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (lease.tenant_id, row["window_id"]),
        )
        changed = conn.execute(
            "UPDATE maintenance_fanout_jobs SET state=%s,lease_until=NULL WHERE tenant_id=%s AND id=%s AND state='pending' AND lease_generation=%s RETURNING id",
            (
                "blocked" if proof_blocked else "pending",
                lease.tenant_id,
                lease.job_id,
                lease.generation,
            ),
        ).fetchone()
        if changed and proof_blocked:
            conn.execute(
                "UPDATE maintenance_windows SET processing_health='blocked' WHERE tenant_id=%s AND id=%s",
                (lease.tenant_id, row["window_id"]),
            )
        return bool(changed)


def derive_current(conn, current, at):
    """Time alone never clears persisted suppression in the current release."""
    tenant, alert_id = current["tenant_id"], current["id"]
    checkpoint = conn.execute(
        """SELECT c.*,h.input_revision AS head_revision FROM maintenance_alert_checkpoints c
        LEFT JOIN maintenance_alert_input_heads h USING(tenant_id,alert_id) WHERE c.tenant_id=%s AND c.alert_id=%s""",
        (tenant, alert_id),
    ).fetchone()
    if (
        not checkpoint
        or not checkpoint["complete"]
        or checkpoint["input_revision"] != checkpoint["head_revision"]
    ):
        raise MaintenanceProofError("maintenance_current_checkpoint_missing")
    return bool(current["suppressed"]), False
