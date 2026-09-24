"""Ordered leased outbox transport. Kafka receipt is not an application effect."""

from dataclasses import dataclass
from hashlib import sha256
from time import monotonic
from uuid import UUID, uuid4

from appchi.ingestion.native import parse_json
from appchi.shared.errors import AppError, unavailable


@dataclass(frozen=True)
class Lease:
    tenant: UUID
    stream: str
    token: UUID
    generation: int
    epoch: str


def claim(db, epoch):
    with db.transaction() as conn:
        conn.execute("""INSERT INTO pipeline_leases(tenant_id,stream)
            SELECT DISTINCT tenant_id,stream FROM application_outbox WHERE published_at IS NULL
            ON CONFLICT DO NOTHING""")
        row = conn.execute("""SELECT l.* FROM pipeline_leases l WHERE NOT blocked
            AND next_attempt_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp())
            AND EXISTS(SELECT 1 FROM application_outbox o WHERE o.tenant_id=l.tenant_id AND o.stream=l.stream AND o.published_at IS NULL)
            ORDER BY next_attempt_at,tenant_id,stream LIMIT 1 FOR UPDATE SKIP LOCKED""").fetchone()
        if not row:
            return None
        token = uuid4()
        conn.execute(
            """UPDATE pipeline_leases SET generation=generation+1,token=%s,epoch=%s,
            lease_until=clock_timestamp()+interval '10 seconds' WHERE tenant_id=%s AND stream=%s""",
            (token, epoch, row["tenant_id"], row["stream"]),
        )
        return Lease(row["tenant_id"], row["stream"], token, row["generation"] + 1, epoch)


def _locked(conn, lease):
    row = conn.execute(
        """SELECT * FROM pipeline_leases WHERE tenant_id=%s AND stream=%s
        AND token=%s AND generation=%s AND epoch=%s AND lease_until>clock_timestamp() FOR UPDATE""",
        (lease.tenant, lease.stream, lease.token, lease.generation, lease.epoch),
    ).fetchone()
    if not row or row["blocked"]:
        raise unavailable("pipeline_lease_lost")
    return row


def head(db, lease):
    with db.transaction() as conn:
        _locked(conn, lease)
        conn.execute(
            "UPDATE pipeline_leases SET lease_until=clock_timestamp()+interval '10 seconds' WHERE tenant_id=%s AND stream=%s",
            (lease.tenant, lease.stream),
        )
        return conn.execute(
            """SELECT * FROM application_outbox WHERE tenant_id=%s AND stream=%s
            AND published_at IS NULL ORDER BY stream_order LIMIT 1""",
            (lease.tenant, lease.stream),
        ).fetchone()


def acknowledge(db, lease, event):
    with db.transaction() as conn:
        _locked(conn, lease)
        current = conn.execute(
            "SELECT id FROM application_outbox WHERE tenant_id=%s AND stream=%s AND published_at IS NULL ORDER BY stream_order LIMIT 1",
            (lease.tenant, lease.stream),
        ).fetchone()
        if not current or current["id"] != event["id"]:
            raise unavailable("pipeline_head_changed")
        conn.execute(
            "UPDATE application_outbox SET published_at=clock_timestamp() WHERE id=%s",
            (event["id"],),
        )
        conn.execute(
            "UPDATE pipeline_leases SET failures=0,lease_until=clock_timestamp()+interval '10 seconds' WHERE tenant_id=%s AND stream=%s",
            (lease.tenant, lease.stream),
        )


def release(db, lease, *, failed=False):
    with db.transaction() as conn:
        conn.execute(
            """UPDATE pipeline_leases SET token=NULL,lease_until=NULL,failures=CASE WHEN %s THEN failures+1 ELSE 0 END,
            next_attempt_at=clock_timestamp()+CASE WHEN %s THEN make_interval(secs=>random()*least(30,power(2,least(failures,5)))) ELSE interval '0 seconds' END
            WHERE tenant_id=%s AND stream=%s AND token=%s AND generation=%s AND epoch=%s""",
            (
                failed,
                failed,
                lease.tenant,
                lease.stream,
                lease.token,
                lease.generation,
                lease.epoch,
            ),
        )


def relay_once(db, settings, producer):
    lease = claim(db, settings.deployment_epoch)
    if lease is None:
        return 0
    start, count = monotonic(), 0
    try:
        while count < 100 and monotonic() - start < 0.1:
            event = head(db, lease)
            if event is None:
                break
            errors = []
            producer.produce(
                f"appchi.{settings.environment}.alerts.{lease.stream}",
                key=lease.tenant.bytes,
                value=bytes(event["envelope"]),
                on_delivery=lambda error, message: errors.append(error),
            )
            if producer.flush(3) > 0 or not errors or errors[0] is not None:
                raise unavailable("kafka_publication_failed")
            acknowledge(db, lease, event)
            count += 1
    except Exception:
        release(db, lease, failed=True)
        raise
    release(db, lease)
    return count


def reference_valid(conn, body, tenant, stream, order):
    from appchi.ingestion.native import canonical

    if stream == "changed":
        if body.get("snapshot_ref") != {"tenant_id": str(tenant), "seq": str(order)}:
            return False
        row = conn.execute(
            "SELECT snapshot,version,alert_id FROM projection_work WHERE tenant_id=%s AND seq=%s",
            (tenant, order),
        ).fetchone()
        return bool(
            row
            and str(row["version"]) == body.get("projection_version")
            and str(row["alert_id"]) == body.get("alert_id")
            and sha256(canonical(row["snapshot"])).hexdigest() == body.get("snapshot_digest")
        )
    if body.get("payload_ref") != {"tenant_id": str(tenant), "item_id": body.get("event_id")}:
        return False
    row = conn.execute(
        "SELECT i.payload,i.version,s.payload AS applied_payload FROM ingest_items i LEFT JOIN alert_source_events s ON s.tenant_id=i.tenant_id AND s.id=i.id WHERE i.tenant_id=%s AND i.id=%s AND i.admission_order=%s",
        (tenant, body.get("event_id"), order),
    ).fetchone()
    return bool(
        row
        and row["version"] == body.get("native_version")
        and sha256(canonical(row["payload"] or row["applied_payload"])).hexdigest()
        == body.get("payload_digest")
    )


def record_receipt(db, *, consumer, topic, partition, offset, key, value, environment):
    """Validate exact persisted envelope before broker offset commit.

    Only a digest and reason are quarantined, never source content or credentials.
    Deterministic bad input remains uncommitted and visible to operations.
    """
    value = value if isinstance(value, bytes) else b""
    stream = {
        "processor": "received",
        "projection": "changed",
        "correlation-wakeup": "changed",
    }.get(consumer)
    reason, tenant, event = None, None, None
    try:
        if stream is None or topic != f"appchi.{environment}.alerts.{stream}" or len(value) > 8192:
            raise ValueError()
        body = parse_json(value)
        tenant = UUID(body["tenant_id"])
        order = body.get("admission_order") if stream == "received" else body.get("projection_seq")
        if (
            type(body.get("schema_version")) is not int
            or body.get("schema_version") != 1
            or body.get("kind") != f"alerts.{stream}"
            or not isinstance(order, str)
            or not order.isascii()
            or not order.isdecimal()
            or str(int(order)) != order
            or not 1 <= int(order) <= 2**63 - 1
            or key != tenant.bytes
        ):
            raise ValueError()
        with db.transaction() as conn:
            event = conn.execute(
                "SELECT id,envelope FROM application_outbox WHERE tenant_id=%s AND stream=%s AND stream_order=%s",
                (tenant, stream, int(order)),
            ).fetchone()
            prior_offset = conn.execute(
                "SELECT outbox_id FROM pipeline_receipts WHERE consumer_name=%s AND topic=%s AND partition=%s AND broker_offset=%s",
                (consumer, topic, partition, offset),
            ).fetchone()
            if (
                not event
                or (prior_offset and prior_offset["outbox_id"] != event["id"])
                or bytes(event["envelope"]) != value
                or not (
                    conn.execute(
                        "SELECT 1 FROM pipeline_receipts WHERE consumer_name=%s AND outbox_id=%s LIMIT 1",
                        (consumer, event["id"]),
                    ).fetchone()
                    or reference_valid(conn, body, tenant, stream, int(order))
                )
            ):
                reason = "pipeline_authoritative_proof_missing"
            else:
                conn.execute(
                    """INSERT INTO pipeline_receipts(consumer_name,topic,partition,broker_offset,tenant_id,outbox_id)
                    VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                    (consumer, topic, partition, offset, tenant, event["id"]),
                )
                return tenant
    except (AppError, ValueError, TypeError, KeyError, AttributeError):
        reason = "pipeline_incompatible_event"
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO pipeline_quarantine(consumer_name,topic,partition,broker_offset,digest,reason)
            VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (consumer, topic, partition, offset, sha256(value).digest(), reason),
        )
        if tenant and stream:
            conn.execute(
                """INSERT INTO pipeline_leases(tenant_id,stream,blocked,reason)
                SELECT id,%s,true,%s FROM tenants WHERE id=%s
                ON CONFLICT(tenant_id,stream) DO UPDATE SET blocked=true,reason=excluded.reason""",
                (stream, reason, tenant),
            )
    raise unavailable(reason)


def consume_once(db, settings, consumer, client):
    message = client.poll(1)
    if message is None:
        return None
    if message.error():
        raise unavailable("kafka_receive_failed")
    try:
        tenant = record_receipt(
            db,
            consumer=consumer,
            topic=message.topic(),
            partition=message.partition(),
            offset=message.offset(),
            key=message.key(),
            value=message.value(),
            environment=settings.environment,
        )
        client.commit(message=message, asynchronous=False)
        return tenant
    except Exception:
        from confluent_kafka import TopicPartition

        # Poll advances the local position even when no offset is committed.
        # Seek back so a later successful record cannot commit past this failure.
        client.seek(TopicPartition(message.topic(), message.partition(), message.offset()))
        raise
