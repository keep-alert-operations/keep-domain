"""Durable rollback-restore fencing. Collection never enables a capability."""

from hashlib import sha256
from math import isfinite
from uuid import UUID, uuid4

from keep.recovery.guard import RESTORE_LOCK
from keep.shared.errors import AppError


def canonical_id(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Canonical UUID required")
    return value


def begin_restore(db, *, run_id, previous_epoch, deployment_epoch, operation_reference):
    """Called with a separately authorized recovery connection after workload quiescence."""
    canonical_id(run_id)
    canonical_id(deployment_epoch)
    if (
        not isinstance(previous_epoch, str)
        or not 1 <= len(previous_epoch) <= 256
        or previous_epoch == deployment_epoch
        or not isinstance(operation_reference, str)
        or not 1 <= len(operation_reference) <= 256
        or any(ord(char) < 32 for char in operation_reference + previous_epoch)
    ):
        raise ValueError("Distinct supplied deployment epochs and operation reference required")
    with db.transaction() as conn:
        # Runtime shared session locks drain before any recovery mutation.
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (RESTORE_LOCK,))
        control = conn.execute(
            "SELECT * FROM restore_control WHERE singleton FOR UPDATE"
        ).fetchone()
        old = conn.execute("SELECT * FROM restore_runs WHERE id=%s", (run_id,)).fetchone()
        if old:
            if (
                old["previous_epoch"],
                str(old["deployment_epoch"]),
                old["operation_reference"],
            ) != (previous_epoch, deployment_epoch, operation_reference):
                raise AppError(
                    "idempotency_conflict", "Recovery operation identity has different inputs.", 409
                )
            if not control or str(control["run_id"]) != run_id or not control["fenced"]:
                raise AppError(
                    "restore_attempt_superseded", "Recovery operation is no longer current.", 409
                )
            return old
        if not control or control["fenced"]:
            raise AppError("restore_already_active", "Resolve the active recovery operation.", 409)
        if (
            control["deployment_epoch"] is not None
            and control["deployment_epoch"] != previous_epoch
        ):
            raise AppError(
                "deployment_epoch_conflict", "Previous deployment authority differs.", 409
            )
        if conn.execute(
            "SELECT 1 FROM restore_runs WHERE deployment_epoch::text=%s OR previous_epoch=%s",
            (deployment_epoch, deployment_epoch),
        ).fetchone():
            raise AppError(
                "deployment_epoch_reused", "A new recovery deployment epoch is required.", 409
            )
        row = conn.execute(
            """INSERT INTO restore_runs(id,previous_epoch,deployment_epoch,operation_reference,state)
            VALUES(%s,%s,%s,%s,'fenced') RETURNING *""",
            (run_id, previous_epoch, deployment_epoch, operation_reference),
        ).fetchone()
        conn.execute(
            "UPDATE restore_control SET deployment_epoch=%s,run_id=%s,fenced=true WHERE singleton",
            (deployment_epoch, run_id),
        )
        conn.execute(
            "UPDATE capability_gates SET ready=false,reason='restore_reconciliation_required'"
        )
        conn.execute(
            "UPDATE auth_sessions SET revoked_at=coalesce(revoked_at,clock_timestamp())"
        )
        return row


def status(db, run_id):
    canonical_id(run_id)
    with db.transaction() as conn:
        row = conn.execute("SELECT * FROM restore_runs WHERE id=%s", (run_id,)).fetchone()
        if not row:
            raise AppError("not_found", "Recovery operation unavailable.", 404)
        return row


def collect_restore(
    db, store, run_id, *, page_size=1000, max_pages=10000, max_records=1000000, deadline_seconds=300
):
    """Stage a complete frozen namespace; never infer missing-family coverage."""
    from keep.recovery.evidence import collect_checkpoint, checkpoint_binding_digest

    canonical_id(run_id)
    if (
        any(
            type(value) is not int or not 1 <= value <= maximum
            for value, maximum in ((page_size, 1000), (max_pages, 10000), (max_records, 1000000))
        )
        or type(deadline_seconds) not in (int, float)
        or not isfinite(deadline_seconds)
        or not 0 < deadline_seconds <= 300
    ):
        raise ValueError("Bounded full-namespace collection limits required")
    collection = uuid4()
    binding_digest = checkpoint_binding_digest(store.binding)
    with db.transaction() as conn:
        _active(conn, run_id)
        conn.execute(
            """UPDATE restore_runs SET state='collecting',collection_id=%s,binding_digest=%s,
            evidence_namespace=%s,snapshot_checkpoint=NULL,collected_count=0,collection_digest=NULL,
            updated_at=clock_timestamp() WHERE id=%s""",
            (collection, binding_digest, store.binding.namespace, run_id),
        )
    count = 0
    pages_digest = sha256()

    def stage(page):
        nonlocal count
        with db.transaction() as conn:
            _active(conn, run_id)
            row = conn.execute(
                "SELECT * FROM restore_runs WHERE id=%s FOR UPDATE", (run_id,)
            ).fetchone()
            if row["collection_id"] != collection or row["binding_digest"] != binding_digest:
                raise AppError(
                    "restore_collection_superseded", "Evidence collection has been superseded.", 409
                )
            records = [
                (
                    run_id,
                    collection,
                    record.id,
                    count + index + 1,
                    record.tenant_id,
                    record.resource_kind,
                    record.resource_id,
                    record.revision,
                    record.state,
                    record.digest,
                )
                for index, record in enumerate(page.records)
            ]
            with conn.cursor() as cursor:
                cursor.executemany(
                    """INSERT INTO restore_evidence_stage(run_id,collection_id,evidence_id,ordinal,tenant_id,
                    resource_kind,resource_id,revision,state,digest) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    records,
                )
            pages_digest.update(bytes.fromhex(page.page_digest))
            count += len(records)
            conn.execute(
                """UPDATE restore_runs SET snapshot_checkpoint=%s,collected_count=%s,collection_digest=%s,
                updated_at=clock_timestamp() WHERE id=%s""",
                (page.checkpoint, count, pages_digest.hexdigest(), run_id),
            )

    summary = collect_checkpoint(
        store,
        stage,
        after=None,
        page_size=page_size,
        max_pages=max_pages,
        max_records=max_records,
        deadline_seconds=deadline_seconds,
    )
    with db.transaction() as conn:
        _active(conn, run_id)
        changed = conn.execute(
            """UPDATE restore_runs SET state='collected',updated_at=clock_timestamp()
            WHERE id=%s AND collection_id=%s AND binding_digest=%s AND evidence_namespace=%s
            AND snapshot_checkpoint=%s AND collected_count=%s AND state='collecting' RETURNING *""",
            (
                run_id,
                collection,
                summary.binding_digest,
                summary.namespace,
                summary.checkpoint,
                summary.records,
            ),
        ).fetchone()
        if not changed:
            raise AppError(
                "restore_collection_superseded", "Evidence collection has been superseded.", 409
            )
        return changed


def _active(conn, run_id):
    control = conn.execute("SELECT * FROM restore_control WHERE singleton FOR SHARE").fetchone()
    if not control or not control["fenced"] or str(control["run_id"]) != run_id:
        raise AppError(
            "restore_attempt_superseded", "Recovery operation is no longer current.", 409
        )
