"""Independent changed-event consumer groups. PostgreSQL stores proof, not work triggers."""

from uuid import UUID
from dataclasses import replace

from appchi.event_models import ChangedEnvelope
from appchi.ingestion.native import parse_json
from appchi.shared.errors import unavailable
from appchi.shared.transactions import coordinator


def correlate_record(db, settings, profile, message):
    envelope = ChangedEnvelope.model_validate(parse_json(message.value()))
    tenant = UUID(envelope.tenant_id)
    if message.key() != tenant.bytes:
        raise unavailable("changed_tenant_key_invalid")
    from appchi.correlation.runtime import prepare_tenant, worker_turn

    with db.transaction(tenant) as conn:
        gate = conn.execute("SELECT ready FROM capability_gates WHERE capability='correlation'").fetchone()
        if not gate or not gate["ready"]:
            raise unavailable("correlation_not_ready")
    prepared = prepare_tenant(db, tenant, profile, allow_local_preview=settings.environment == "development")
    with db.transaction(tenant) as conn:
        coordinator(conn, tenant)
        if prepared.maintenance:
            from appchi.maintenance.runtime import InlineCorrelation, lock_catalog
            catalog = replace(prepared.maintenance, inline_correlation=InlineCorrelation(db, profile, prepared))
            lock_catalog(conn, catalog, targets=[envelope.alert_id])
        duplicate = conn.execute("SELECT 1 FROM kafka_correlation_events WHERE event_id=%s", (envelope.event_id,)).fetchone()
        if not duplicate and envelope.cause == "source":
            source = conn.execute("SELECT r.changed_envelope,i.retired_at FROM kafka_source_results r LEFT JOIN alert_identities i ON i.tenant_id=r.tenant_id AND i.id=r.alert_id WHERE r.tenant_id=%s AND r.changed_event_id=%s", (tenant, envelope.event_id)).fetchone()
            if not source or (not source["retired_at"] and (source["changed_envelope"] is None or bytes(source["changed_envelope"]) != message.value())):
                raise unavailable("correlation_envelope_proof_invalid")
            proof = conn.execute("SELECT p.snapshot,j.* FROM projection_work p LEFT JOIN correlation_journal j ON j.tenant_id=p.tenant_id AND j.alert_id=p.alert_id AND j.change_order=%s AND j.after_snapshot->>'history_id'=p.snapshot->>'history_id' WHERE p.tenant_id=%s AND p.seq=%s", (int(envelope.change_order), tenant, int(envelope.projection_seq))).fetchone()
            if not proof:
                retired = conn.execute("SELECT retired_at FROM alert_identities WHERE tenant_id=%s AND id=%s", (tenant, envelope.alert_id)).fetchone()
                if not retired or not retired["retired_at"]:
                    raise unavailable("correlation_transition_proof_missing")
            elif proof["change_order"] is not None:
                event = dict(proof, stream="kafka")
                worker_turn(db, tenant, profile, prepared_input=prepared, input_event=event, transaction=conn, kafka=True)
                # Candidate arbitration completes before this Kafka input advances.
                while (state := conn.execute("SELECT pending FROM correlation_consumer_state WHERE tenant_id=%s", (tenant,)).fetchone()) and state["pending"]:
                    if not worker_turn(db, tenant, profile, prepared_input=prepared, transaction=conn, kafka=True):
                        break
        conn.execute("INSERT INTO kafka_correlation_events(event_id,tenant_id,topic,partition,input_offset) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING", (envelope.event_id, tenant, message.topic(), message.partition(), message.offset()))
        if not duplicate and envelope.cause == "source" and prepared.maintenance:
            from appchi.maintenance.runtime import publish_inline_effects
            publish_inline_effects(conn, {"tenant_id": tenant, "id": envelope.alert_id})
    return envelope


class ChangedConsumer:
    def __init__(self, db, settings, profile, role):
        from confluent_kafka import Consumer
        from appchi.service_clients import kafka_options

        self.db, self.settings, self.profile, self.role = db, settings, profile, role
        self.closing = False
        with db.transaction() as conn:
            self.control = conn.execute("SELECT * FROM kafka_pipeline_control WHERE singleton").fetchone()
            if not self.control["enabled"]:
                raise unavailable("kafka_cutover_required")
        self.client = Consumer({**kafka_options(settings), "group.id": f"appchi.{settings.environment}.{role}-v2",
            "enable.auto.commit": False, "enable.auto.offset.store": False, "isolation.level": "read_committed",
            "auto.offset.reset": "error"})
        self.client.subscribe([f"appchi.{settings.environment}.alerts.changed"], on_assign=self._assign)

    def _assign(self, client, partitions):
        if self.closing:
            return
        topic = f"appchi.{self.settings.environment}.alerts.changed"
        if len(client.list_topics(topic,timeout=5).topics[topic].partitions) != self.control["changed_partitions"]:
            raise unavailable("kafka_partition_topology_changed")
        for p in partitions:
            offset = client.committed([p], timeout=5)[0].offset
            low, _ = client.get_watermark_offsets(p, timeout=5)
            if offset < 0 and low == 0:
                offset = 0
            if offset < low:
                with self.db.transaction() as conn:
                    conn.execute("INSERT INTO kafka_pipeline_faults(consumer,topic,partition,input_offset,reason) VALUES(%s,%s,%s,%s,'retention_gap') ON CONFLICT DO NOTHING", (self.role, p.topic, p.partition, max(0, offset)))
                # Search can reconstruct; correlation must expose a lost decision
                # interval and requires a reviewed fresh-boundary reset.
                if self.role == "correlation":
                    raise unavailable("correlation_retention_gap")
                offset = low
            p.offset = offset
        client.assign(partitions)

    def turn(self):
        message = self.client.poll(0.1)
        if message is None:
            return 0
        if message.error():
            raise unavailable("changed_consume_failed")
        if self.role == "correlation":
            correlate_record(self.db, self.settings, self.profile, message)
        else:
            envelope = ChangedEnvelope.model_validate(parse_json(message.value()))
            if message.key() != UUID(envelope.tenant_id).bytes:
                raise unavailable("changed_tenant_key_invalid")
            from appchi.search.reconciliation import project_alert
            project_alert(self.db, self.settings, UUID(envelope.tenant_id), UUID(envelope.alert_id))
        self.client.commit(message=message, asynchronous=False)
        with self.db.transaction() as conn:
            conn.execute("""INSERT INTO kafka_consumer_positions(consumer,topic,partition,next_offset) VALUES(%s,%s,%s,%s)
                ON CONFLICT(consumer,topic,partition) DO UPDATE SET next_offset=greatest(kafka_consumer_positions.next_offset,EXCLUDED.next_offset),updated_at=clock_timestamp()""", (self.role, message.topic(), message.partition(), message.offset()+1))
        return 1

    def close(self):
        self.closing = True
        self.client.close()
