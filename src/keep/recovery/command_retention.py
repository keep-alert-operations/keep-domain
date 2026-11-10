"""Ordinary completed-command lifetime and independently protected body erasure.

Descriptors retain original job references so pending work cannot age out and
later operator jobs cannot accidentally extend or shorten an earlier command.
Unknown scopes and missing dependency proofs are deliberately not age-expired.
"""

from dataclasses import asdict, dataclass
from datetime import timedelta
from hashlib import sha256
from time import monotonic
from uuid import UUID, uuid5

from psycopg import sql
from psycopg.types.json import Jsonb

from keep.ingestion.native import canonical
from keep.recovery.cleanup import COMMAND_NAMESPACE, _command_evidence
from keep.recovery.evidence import append_verified
from keep.recovery.incidents import ready
from keep.shared.errors import AppError, unavailable


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError):
        return False


def classify(scope, result):
    """Allowlist existing server namespaces; parent-owned families never qualify."""
    parts = scope.split(":")
    if len(parts) == 2 and _uuid(parts[0]) and parts[1] == "tenant-create":
        tenant = result.get("data", {}).get("id") if isinstance(result, dict) else None
        return (tenant, "tenant", False) if _uuid(tenant) else None
    if len(parts) < 3 or not all(_uuid(value) for value in parts[:2]):
        return None
    tenant, _, family, *tail = parts
    if not tail and family in {"tenant-rename", "permissions"}:
        return tenant, "tenant", False
    if not tail and family == "source-processing-retry":
        return tenant, family, False
    if not tail and family in {"operator-create", "operator-copy"}:
        return tenant, "operator", False
    if (
        family == "operator"
        and len(tail) == 1
        and tail[0]
        in {"rename", "delete", "rotate", "create_key", "revoke", "revoke_all", "cancel", "retry"}
    ):
        return tenant, "operator", False
    if family in {"presets", "dashboards"}:
        if len(tail) == 1 and (tail[0] in {"create", "delete"} or _uuid(tail[0])):
            return tenant, family[:-1], tail[0] == "delete"
        if family == "presets" and len(tail) == 2 and tail[0] == "delete" and _uuid(tail[1]):
            return tenant, "preset", True
    if family in {"maintenance", "correlation"} and len(tail) == 2:
        target, operation = tail
        if (target == "create" or _uuid(target)) and operation in {
            "create",
            "edit",
            "replace",
            "enable",
            "disable",
            "delete",
        }:
            return tenant, family, operation == "delete"
    return None


DELETE_TABLES = {
    "configuration_delete_id": "configuration_delete_jobs",
    "maintenance_delete_id": "maintenance_delete_jobs",
    "correlation_delete_id": "correlation_delete_jobs",
}


def register(conn, receipt):
    """Register new or restored legacy receipts without inferring missing proof."""
    scope, command = receipt["scope"], receipt["command_id"]
    existing = conn.execute(
        "SELECT * FROM command_retention WHERE scope=%s AND command_id=%s", (scope, command)
    ).fetchone()
    if existing:
        return existing
    if receipt["result"] is None:
        return None
    parsed = classify(scope, receipt["result"])
    if (
        parsed is None
        or conn.execute(
            "SELECT 1 FROM command_resources WHERE scope=%s AND command_id=%s", (scope, command)
        ).fetchone()
    ):
        return None
    tenant, family, deleting = parsed
    if not conn.execute("SELECT 1 FROM tenants WHERE id=%s", (tenant,)).fetchone():
        return None
    dependencies = {key: None for key in DELETE_TABLES}
    operation = None
    if family == "operator":
        data = receipt["result"].get("data", {})
        if not isinstance(data, dict):
            return None
        original = data.get("operation")
        if original is not None:
            if not isinstance(original, dict) or not _uuid(original.get("id")):
                return None
            operation = conn.execute(
                "SELECT id FROM operator_operations WHERE tenant_id=%s AND id=%s",
                (tenant, original["id"]),
            ).fetchone()
            if not operation:
                return None
            operation = operation["id"]
        elif receipt["status"] == 202:
            return None
    if deleting:
        column = {
            "preset": "configuration_delete_id",
            "dashboard": "configuration_delete_id",
            "maintenance": "maintenance_delete_id",
            "correlation": "correlation_delete_id",
        }[family]
        job = conn.execute(
            sql.SQL("SELECT id FROM {} WHERE tenant_id=%s AND scope=%s AND command_id=%s").format(
                sql.Identifier(DELETE_TABLES[column])
            ),
            (tenant, scope, command),
        ).fetchone()
        if not job:
            return None
        dependencies[column] = job["id"]
    conn.execute(
        """INSERT INTO command_retention(scope,command_id,tenant_id,family,operator_operation_id,
        configuration_delete_id,maintenance_delete_id,correlation_delete_id)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(scope,command_id) DO NOTHING""",
        (scope, command, tenant, family, operation, *dependencies.values()),
    )
    return conn.execute(
        "SELECT * FROM command_retention WHERE scope=%s AND command_id=%s", (scope, command)
    ).fetchone()


def expired(conn, receipt):
    descriptor = register(conn, receipt)
    if (
        not descriptor
        or conn.execute(
            "SELECT 1 FROM command_resources WHERE scope=%s AND command_id=%s",
            (receipt["scope"], receipt["command_id"]),
        ).fetchone()
    ):
        return False
    if conn.execute(
        "SELECT 1 FROM command_retention_holds WHERE scope=%s AND command_id=%s AND released_at IS NULL",
        (receipt["scope"], receipt["command_id"]),
    ).fetchone():
        return False
    completed = receipt["completed_at"]
    if descriptor["operator_operation_id"]:
        job = conn.execute(
            "SELECT state,completed_at FROM operator_operations WHERE id=%s",
            (descriptor["operator_operation_id"],),
        ).fetchone()
        if (
            not job
            or job["state"] not in {"completed", "cancelled", "superseded"}
            or job["completed_at"] is None
        ):
            return False
        completed = max(completed, job["completed_at"])
    for column, table in DELETE_TABLES.items():
        if descriptor[column]:
            job = conn.execute(
                sql.SQL("SELECT state,final_ack,updated_at FROM {} WHERE id=%s").format(
                    sql.Identifier(table)
                ),
                (descriptor[column],),
            ).fetchone()
            if not job or job["state"] != "final_protected" or not job["final_ack"]:
                return False
            completed = max(completed, job["updated_at"])
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    return completed + timedelta(days=90) <= now


def compact_ordinary_command(db, store, scope, command):
    with db.transaction() as conn:
        ready(conn)
        receipt = conn.execute(
            "SELECT * FROM command_receipts WHERE scope=%s AND command_id=%s FOR UPDATE",
            (scope, command),
        ).fetchone()
        if not receipt or receipt["result"] is None or not expired(conn, receipt):
            return False
        descriptor = register(conn, receipt)
        tenant = descriptor["tenant_id"]
        job = conn.execute(
            "SELECT * FROM command_content_retirements WHERE scope=%s AND command_id=%s",
            (scope, command),
        ).fetchone()
        if not job:
            identity = uuid5(COMMAND_NAMESPACE, scope + ":" + str(command))
            result_digest = sha256(canonical(receipt["result"])).hexdigest()
            digest = sha256(
                canonical(
                    {
                        "scope": scope,
                        "command_id": str(command),
                        "fingerprint": bytes(receipt["fingerprint"]).hex(),
                        "status": receipt["status"],
                        "result_digest": result_digest,
                    }
                )
            ).hexdigest()
            job = conn.execute(
                """INSERT INTO command_content_retirements(id,scope,command_id,tenant_id,fingerprint,
                result_digest,evidence_digest,intent_id,final_id,state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared') RETURNING *""",
                (
                    identity,
                    scope,
                    command,
                    tenant,
                    receipt["fingerprint"],
                    result_digest,
                    digest,
                    uuid5(identity, "intent"),
                    uuid5(identity, "final"),
                ),
            ).fetchone()
    if job["state"] == "prepared":
        intent = append_verified(store, _command_evidence(job, "intent"))
        final = append_verified(store, _command_evidence(job, "final"))
        with db.transaction() as conn:
            conn.execute(
                """UPDATE command_content_retirements SET state='final_protected',intent_ack=%s,
                final_ack=%s,updated_at=clock_timestamp() WHERE id=%s AND state='prepared'""",
                (Jsonb(asdict(intent)), Jsonb(asdict(final)), job["id"]),
            )
    with db.transaction() as conn:
        ready(conn)
        receipt = conn.execute(
            "SELECT * FROM command_receipts WHERE scope=%s AND command_id=%s FOR UPDATE",
            (scope, command),
        ).fetchone()
        current = conn.execute(
            "SELECT * FROM command_content_retirements WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if current["state"] == "cleaned":
            return True
        if not expired(conn, receipt):
            return False
        if (
            current["state"] != "final_protected"
            or not current["final_ack"]
            or bytes(receipt["fingerprint"]) != bytes(job["fingerprint"])
            or sha256(canonical(receipt["result"])).hexdigest() != job["result_digest"]
        ):
            raise unavailable("command_erasure_precondition_changed")
        for column, table in DELETE_TABLES.items():
            if descriptor[column]:
                conn.execute(
                    sql.SQL(
                        "UPDATE {} SET receipt=NULL WHERE id=%s AND state='final_protected'"
                    ).format(sql.Identifier(table)),
                    (descriptor[column],),
                )
        conn.execute(
            "UPDATE command_receipts SET result=NULL WHERE scope=%s AND command_id=%s",
            (scope, command),
        )
        # Completion dependencies protect body retention only. Release their FKs
        # once the permanent receipt/evidence fence replaces that body, so this
        # minimal record cannot hold entire completed jobs forever.
        conn.execute(
            """UPDATE command_retention SET operator_operation_id=NULL,configuration_delete_id=NULL,
            maintenance_delete_id=NULL,correlation_delete_id=NULL WHERE scope=%s AND command_id=%s""",
            (scope, command),
        )
        conn.execute(
            "UPDATE command_content_retirements SET state='cleaned',updated_at=clock_timestamp() WHERE id=%s",
            (job["id"],),
        )
    return True


@dataclass(frozen=True)
class CommandRetentionPage:
    attempted: int
    completed: int
    deferred: int
    cursor: tuple | None


def command_retention_turn(db, store, *, cursor=None, limit=100):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Command retention limit must be 1..100")
    with db.transaction() as conn:
        ready(conn)
        rows = conn.execute(
            """SELECT completed_at,scope,command_id FROM command_receipts
            WHERE result IS NOT NULL AND completed_at<=clock_timestamp()-interval '90 days'
            AND (%s::timestamptz IS NULL OR (completed_at,scope,command_id)>(%s::timestamptz,%s::text,%s::uuid))
            ORDER BY completed_at,scope,command_id LIMIT %s""",
            (cursor[0] if cursor else None, *(cursor or (None, None, None)), limit + 1),
        ).fetchall()
    started = monotonic()
    attempted = completed = deferred = 0
    last = None
    for row in rows[:limit]:
        try:
            done = compact_ordinary_command(db, store, row["scope"], row["command_id"])
        except AppError:
            done = False
        attempted += 1
        completed += int(done)
        deferred += int(not done)
        last = (row["completed_at"], row["scope"], row["command_id"])
        if monotonic() - started >= 0.1:
            break
    return CommandRetentionPage(
        attempted, completed, deferred, last if len(rows) > attempted else None
    )
