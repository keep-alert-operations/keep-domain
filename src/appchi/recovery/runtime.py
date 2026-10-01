"""Application retirement host; every external call is outside SQL locks."""

import json
from dataclasses import dataclass
from time import monotonic

from appchi.recovery.evidence import EvidenceBinding, HttpEvidenceStore
from appchi.recovery.retirement import retire_alert
from appchi.shared.errors import AppError, unavailable


def configured_store(settings):
    if not settings.recovery_binding or not settings.recovery_credential:
        raise unavailable("recovery_binding_required")
    body = json.loads(settings.recovery_binding.read_text(encoding="utf-8"))
    return HttpEvidenceStore(
        EvidenceBinding(**body), settings.recovery_credential.get_secret_value()
    )


@dataclass(frozen=True)
class RetirementPage:
    attempted: int
    completed: int
    deferred: int
    cursor: tuple[str, str] | None
    progress_pending: bool = False


def retirement_turn(db, store, *, cursor=None):
    with db.transaction() as conn:
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='recovery'"
        ).fetchone()
        if not gate or not gate["ready"]:
            raise unavailable("recovery_not_ready")
        rows = conn.execute(
            """SELECT tenant_id,id FROM (
            SELECT a.tenant_id,a.id FROM alerts a JOIN alert_identities i ON i.tenant_id=a.tenant_id AND i.id=a.id
            WHERE i.retired_at IS NULL AND a.status='resolved' AND a.retention_at<=clock_timestamp()
            UNION SELECT tenant_id,resource_id AS id FROM retirement_jobs WHERE resource_kind='alert'
            AND (state IN ('intent','retired','final_protected') OR (state='cancelled' AND cancel_ack IS NULL))
            ) candidates WHERE (%s::uuid IS NULL OR (tenant_id,id)>(%s::uuid,%s::uuid))
            ORDER BY tenant_id,id LIMIT 101""",
            (cursor[0] if cursor else None, *(cursor or (None, None))),
        ).fetchall()
    start = monotonic()
    completed = deferred = attempted = 0
    progress_pending = False
    last = None
    for row in rows[:100]:
        try:
            from appchi.recovery.alert_cleanup import cleanup_alert

            if retire_alert(db, store, row["tenant_id"], row["id"]):
                cleaned = cleanup_alert(db, store, row["tenant_id"], row["id"])
                completed += int(cleaned)
                progress_pending = progress_pending or not cleaned
        except AppError as error:
            if error.code not in (
                "source_updates_pending",
                "not_found",
                "recovery_protection_unavailable",
            ):
                raise
            deferred += 1
        attempted += 1
        last = (str(row["tenant_id"]), str(row["id"]))
        if monotonic() - start >= 0.1:
            break
    more = len(rows) > attempted
    return RetirementPage(attempted, completed, deferred, last if more else None, progress_pending)


@dataclass(frozen=True)
class IncidentRetirementPage(RetirementPage):
    progress_pending: bool = False


def incident_retirement_turn(db, store, *, cursor=None):
    from appchi.recovery.incidents import retire_incident, ready
    from appchi.recovery.cleanup import cleanup_incident

    with db.transaction() as conn:
        ready(conn)
        rows = conn.execute(
            """SELECT tenant_id,id FROM (
            SELECT i.tenant_id,i.id FROM incidents i JOIN incident_identities x ON x.tenant_id=i.tenant_id AND x.id=i.id
              WHERE x.retired_at IS NULL AND i.status='resolved' AND i.retention_at<=clock_timestamp()
            UNION SELECT tenant_id,resource_id FROM retirement_jobs WHERE resource_kind='incident'
              AND (state IN ('intent','retired','final_protected') OR (state='cancelled' AND cancel_ack IS NULL))
            UNION SELECT l.tenant_id,l.incident_id FROM incident_alert_links l
              JOIN incident_identities i ON i.tenant_id=l.tenant_id AND i.id=l.incident_id
              JOIN alert_identities a ON a.tenant_id=l.tenant_id AND a.id=l.alert_id
              WHERE i.retired_at IS NOT NULL AND a.retired_at IS NOT NULL
              AND EXISTS (SELECT 1 FROM retirement_jobs j WHERE j.tenant_id=l.tenant_id
                AND j.resource_kind='alert' AND j.resource_id=l.alert_id
                AND j.state IN ('final_protected','cleaned') AND j.final_ack IS NOT NULL)
            ) pending WHERE (%s::uuid IS NULL OR (tenant_id,id)>(%s::uuid,%s::uuid))
            ORDER BY tenant_id,id LIMIT 101""",
            (cursor[0] if cursor else None, *(cursor or (None, None))),
        ).fetchall()
    start = monotonic()
    attempted = completed = deferred = 0
    last = None
    progress_pending = False
    for row in rows[:100]:
        try:
            if retire_incident(db, store, row["tenant_id"], row["id"]):
                cleaned = cleanup_incident(db, store, row["tenant_id"], row["id"])
                completed += int(cleaned)
                progress_pending = progress_pending or not cleaned
            else:
                deferred += 1
        except AppError:
            deferred += 1
        attempted += 1
        last = (str(row["tenant_id"]), str(row["id"]))
        if monotonic() - start >= 0.1:
            break
    return IncidentRetirementPage(
        attempted, completed, deferred, last if len(rows) > attempted else None, progress_pending
    )
