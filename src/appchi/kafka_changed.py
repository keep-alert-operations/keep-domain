"""Independent changed-event consumer groups. PostgreSQL stores proof, not work triggers."""

from appchi.shared.errors import unavailable


class ChangedConsumer:
    def __init__(self, db, settings, profile, role, handler):
        from confluent_kafka import Consumer
        from appchi.service_clients import kafka_options

        self.db, self.settings, self.profile, self.role = db, settings, profile, role
        self.handler = handler
        self.closing = False
        with db.transaction() as conn:
            self.control = conn.execute(
                "SELECT * FROM kafka_pipeline_control WHERE singleton"
            ).fetchone()
            if not self.control["enabled"]:
                raise unavailable("kafka_cutover_required")
        self.client = Consumer(
            {
                **kafka_options(settings),
                "group.id": f"appchi.{settings.environment}.{role}-v2",
                "enable.auto.commit": False,
                "enable.auto.offset.store": False,
                "isolation.level": "read_committed",
                "auto.offset.reset": "error",
            }
        )
        self.client.subscribe(
            [f"appchi.{settings.environment}.alerts.changed"], on_assign=self._assign
        )

    def _assign(self, client, partitions):
        if self.closing:
            return
        topic = f"appchi.{self.settings.environment}.alerts.changed"
        if (
            len(client.list_topics(topic, timeout=5).topics[topic].partitions)
            != self.control["changed_partitions"]
        ):
            raise unavailable("kafka_partition_topology_changed")
        for p in partitions:
            offset = client.committed([p], timeout=5)[0].offset
            low, _ = client.get_watermark_offsets(p, timeout=5)
            if offset < 0 and low == 0:
                offset = 0
            if offset < low:
                with self.db.transaction() as conn:
                    conn.execute(
                        "INSERT INTO kafka_pipeline_faults(consumer,topic,partition,input_offset,reason) VALUES(%s,%s,%s,%s,'retention_gap') ON CONFLICT DO NOTHING",
                        (self.role, p.topic, p.partition, max(0, offset)),
                    )
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
        self.handler(self.db, self.settings, self.profile, message)
        self.client.commit(message=message, asynchronous=False)
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO kafka_consumer_positions(consumer,topic,partition,next_offset) VALUES(%s,%s,%s,%s)
                ON CONFLICT(consumer,topic,partition) DO UPDATE SET next_offset=greatest(kafka_consumer_positions.next_offset,EXCLUDED.next_offset),updated_at=clock_timestamp()""",
                (self.role, message.topic(), message.partition(), message.offset() + 1),
            )
        return 1

    def close(self):
        self.closing = True
        self.client.close()
