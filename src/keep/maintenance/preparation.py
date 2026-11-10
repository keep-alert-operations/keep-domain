"""Optimistic historical proof preparation outside tenant writer transactions.

Immutable inputs are keyset-read in bounded, short read transactions. The result
is usable only at its exact input-head/catalog fence. Source prediction also
binds the expected input UUID/digest, so an intervening command requires retry.
No prepared result is a substitute for the writer's normal validation/locks.
"""

from dataclasses import asdict, dataclass, replace
from contextlib import contextmanager
from datetime import datetime
import hashlib
from uuid import UUID, uuid5

from keep.ingestion.native import canonical
from keep.serialization import wire
from keep.shared.errors import unavailable

from .incremental import checkpoint
from .temporal import AlertTransition, Boundary, reduce_alert


@contextmanager
def _read(database, tenant):
    # Tenant-scoped Database.transaction executes set_config itself. Select the
    # isolation mode before that first query, then bind RLS explicitly.
    with database.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SELECT set_config('keep.tenant_id',%s,true)", (str(tenant),))
        yield conn


@dataclass(frozen=True)
class PreparedReplay:
    input_revision: int
    last_id: UUID
    last_digest: bytes
    result: object
    continuation: dict
    digest: bytes
    previous_qualifiers: dict
    withdrawn: tuple
    history_intervals: list
    predicted: bool


def bind_source(proof, row, alert_id):
    """Relabel a predicted final source after unrelated tenant work advances.

    The caller first checks the same-alert head/catalog and exact source proof.
    Both order labels follow all retained inputs/controls. Their relative order
    is identical, so evaluation/intervals need no replay. Only the bounded delta
    and live continuation contain the new input's identity/order.
    """
    from .incremental import _cause

    if (
        not proof.predicted
        or row["kind"] != "source"
        or bytes(row["request_digest"]) != proof.last_digest
        or row["effective_at"] != datetime.fromisoformat(proof.continuation["last_at"])
    ):
        raise unavailable("maintenance_preparation_changed")
    old_id, new_id = str(proof.last_id), str(row["id"])

    def boundary(value):
        return (
            replace(value, order=row["original_order"], id=new_id)
            if value and value.id == old_id
            else value
        )

    def cause(value):
        opened = boundary(value.opened)
        return replace(
            value,
            opened=opened,
            closed=boundary(value.closed),
            id=uuid5(alert_id, value.cause_id + ":" + new_id)
            if value.opened.id == old_id
            else value.id,
        )

    result = replace(
        proof.result,
        causes=tuple(cause(value) for value in proof.result.causes),
        qualifier_inputs=tuple(
            (
                at,
                new_id if input_id == old_id else input_id,
                allowed,
                new_id if origin == old_id else origin,
            )
            for at, input_id, allowed, origin in proof.result.qualifier_inputs
        ),
    )
    continuation = wire(
        {
            **proof.continuation,
            "last_order": row["original_order"],
            "causes": [asdict(cause(_cause(value))) for value in proof.continuation["causes"]],
        }
    )
    digest = hashlib.sha256(
        canonical(
            {
                "prepared": proof.digest.hex(),
                "input_id": new_id,
                "input_order": row["original_order"],
                "input_digest": proof.last_digest.hex(),
            }
        )
    ).digest()
    return replace(
        proof, result=result, continuation=continuation, last_id=row["id"], digest=digest
    )


def prepare_replay(database, catalog, alert_id, *, source_item=None):
    from .processing import _snapshot

    tenant = catalog.tenant_id
    alert_id = UUID(str(alert_id))
    with _read(database, tenant) as conn:
        head = conn.execute(
            "SELECT input_revision,last_input_id FROM maintenance_alert_input_heads WHERE tenant_id=%s AND alert_id=%s",
            (tenant, alert_id),
        ).fetchone()
        current = conn.execute(
            "SELECT * FROM alerts WHERE tenant_id=%s AND id=%s", (tenant, alert_id)
        ).fetchone()
        if not head or not current:
            return None
        tail = conn.execute(
            "SELECT original_order FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s AND id=%s",
            (tenant, alert_id, head["last_input_id"]),
        ).fetchone()
        state = conn.execute(
            "SELECT admission_order,clock_timestamp() AS now FROM tenant_work_state WHERE tenant_id=%s",
            (tenant,),
        ).fetchone()
    rows, position = [], 0
    while True:
        with _read(database, tenant) as conn:
            page = conn.execute(
                """SELECT * FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s
                AND original_order>%s AND original_order<=%s ORDER BY original_order LIMIT %s""",
                (tenant, alert_id, position, tail["original_order"], catalog.max_inputs),
            ).fetchall()
        rows.extend(page)
        if len(page) < catalog.max_inputs:
            break
        position = page[-1]["original_order"]
    if len(rows) != head["input_revision"]:
        raise unavailable("maintenance_preparation_changed")
    old_qualifiers, known_events = {}, set()
    for table, columns in (
        ("maintenance_cause_history", "id"),
        ("maintenance_qualifier_effects", "*"),
    ):
        position_id = UUID(int=0)
        while True:
            with _read(database, tenant) as conn:
                page = conn.execute(
                    f"SELECT {columns} FROM {table} WHERE tenant_id=%s AND alert_id=%s AND id>%s ORDER BY id LIMIT %s",
                    (tenant, alert_id, position_id, catalog.max_inputs),
                ).fetchall()
            if table == "maintenance_cause_history":
                known_events.update(row["id"] for row in page)
            else:
                old_qualifiers.update({row["id"]: row for row in page})
            if len(page) < catalog.max_inputs:
                break
            position_id = page[-1]["id"]
    # These relations can change only behind the same coordinator. Revalidate
    # the input/catalog fence after reading them, before doing expensive work.
    with _read(database, tenant) as conn:
        check = conn.execute(
            """SELECT h.input_revision,v.maintenance_generation FROM maintenance_alert_input_heads h
            JOIN tenant_view_state v USING(tenant_id) WHERE h.tenant_id=%s AND h.alert_id=%s""",
            (tenant, alert_id),
        ).fetchone()
        if (
            not check
            or check["input_revision"] != head["input_revision"]
            or check["maintenance_generation"] != catalog.generation
        ):
            raise unavailable("maintenance_preparation_changed")
    now = state["now"]
    predicted = source_item is not None
    if predicted:
        from keep.alerts.lifecycle import apply_source

        after, _ = apply_source(current, source_item)
        before, after_snapshot = _snapshot(current), _snapshot(after)
        order = source_item.get("admission_order", state["admission_order"] + 1)
        at = source_item["received_at"]
        # record_input uses UTC explicitly, independent of the host timezone.
        from datetime import UTC

        identity = uuid5(alert_id, f"input:{at.astimezone(UTC).isoformat()}:{order}")
        digest = hashlib.sha256(
            canonical(
                {
                    "before": before,
                    "after": after_snapshot,
                    "cause": "source",
                    "source_suppressed": after["source_suppressed"],
                }
            )
        ).digest()
        rows.append(
            {
                "id": identity,
                "effective_at": at,
                "original_order": order,
                "before_snapshot": before,
                "after_snapshot": after_snapshot,
                "new_logical_alert": False,
                "source_suppressed": after["source_suppressed"],
                "kind": "source",
                "request_digest": digest,
            }
        )
        now = max(now, at)
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
    result = reduce_alert(
        alert_id,
        catalog.segments,
        transitions,
        now=now,
        recorded_at=now,
        proof_complete=bool(rows and rows[0]["new_logical_alert"]),
        max_work=catalog.max_work,
        source_release_since=catalog.source_release_since,
        per_input_budget=True,
    )
    continuation = checkpoint(
        result,
        rows[-1],
        generation=catalog.generation,
        source_release_since=catalog.source_release_since,
        max_at=max(row["effective_at"] for row in rows),
    )
    evidence = {
        "inputs": [bytes(row["request_digest"]).hex() for row in rows],
        "generation": catalog.generation,
        "continuation": continuation,
    }
    digest = hashlib.sha256(canonical(evidence)).digest()
    causes = tuple(
        cause
        for cause in result.causes
        if any(
            boundary is not None and uuid5(cause.id, kind + ":" + boundary.id) not in known_events
            for kind, boundary in (("open", cause.opened), ("close", cause.closed))
        )
    )
    desired, changed = {}, []
    for at, input_id, allowed, origin in result.qualifier_inputs:
        identity = uuid5(alert_id, "final-unsuppression:" + at.isoformat())
        desired[identity] = at
        previous = old_qualifiers.get(identity)
        if (
            not previous
            or not previous["active"]
            or (
                str(previous["source_input_id"]),
                previous["correlation_allowed"],
                str(previous["origin_input_id"]) if previous["origin_input_id"] else None,
            )
            != (input_id, allowed, origin)
        ):
            changed.append((at, input_id, allowed, origin))
    withdrawn = tuple(
        identity
        for identity, row in old_qualifiers.items()
        if row["active"] and identity not in desired
    )
    selected = {
        uuid5(alert_id, "final-unsuppression:" + item[0].isoformat()) for item in changed
    } | set(withdrawn)
    intervals = wire(
        [{"start": interval.start, "end": interval.end} for interval in result.effective_intervals]
    )
    delta = replace(
        result,
        causes=causes,
        effective_intervals=result.effective_intervals[-1:],
        final_unsuppression_qualifiers=tuple(item[0] for item in changed),
        qualifier_inputs=tuple(changed),
    )
    return PreparedReplay(
        head["input_revision"] + int(predicted),
        rows[-1]["id"],
        bytes(rows[-1]["request_digest"]),
        delta,
        continuation,
        digest,
        {key: value for key, value in old_qualifiers.items() if key in selected},
        withdrawn,
        intervals,
        predicted,
    )
