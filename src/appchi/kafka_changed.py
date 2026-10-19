"""Independent changed-event consumer groups. PostgreSQL stores proof, not work triggers."""

from collections import deque
from time import monotonic
import logging

from appchi.shared.errors import unavailable

log = logging.getLogger(__name__)


class PartitionRetries:
    """Retain failed offsets without repeatedly rebalancing healthy partitions."""

    def __init__(self, client):
        self.client = client
        self.failed = {}

    def fail(self, message, *, delay=5):
        from confluent_kafka import TopicPartition

        point = TopicPartition(message.topic(), message.partition(), message.offset())
        self.client.pause([point])
        self.client.seek(point)
        self.failed[(point.topic, point.partition)] = (point, monotonic() + delay)

    def timeout(self, limit):
        """Bound an idle poll so a short retry resumes near its deadline."""
        due = min((deadline for _, deadline in self.failed.values()), default=float("inf"))
        return max(0.0, min(limit, due - monotonic()))

    def resume_due(self):
        now = monotonic()
        for key, (point, deadline) in list(self.failed.items()):
            if deadline <= now:
                self.client.seek(point)
                self.client.resume([point])
                del self.failed[key]

    def revoke(self, partitions):
        for point in partitions:
            self.failed.pop((point.topic, point.partition), None)

    def fence(self, point):
        # Retention loss needs an explicit repair/restart, not a timed retry.
        # Assignment uses the broker low offset but this partition is paused
        # before polling, and no group offset is advanced by the fence.
        self.client.pause([point])
        self.failed[(point.topic, point.partition)] = (point, float("inf"))


class ChangedConsumer:
    def __init__(self, db, settings, profile, role, handler, *, batch_handler=None, batch_size=50):
        from confluent_kafka import Consumer
        from appchi.service_clients import kafka_options

        self.db, self.settings, self.profile, self.role = db, settings, profile, role
        self.handler = handler
        self.batch_handler = batch_handler
        self.batch_size = min(50, max(1, batch_size))
        self.pending = deque()
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
        self.retries = PartitionRetries(self.client)
        self.client.subscribe(
            [f"appchi.{settings.environment}.alerts.changed"],
            on_assign=self._assign,
            on_revoke=self._revoke,
        )

    def _revoke(self, client, partitions):
        revoked = {(p.topic, p.partition) for p in partitions}
        self.pending = deque(
            group
            for group in self.pending
            if (group[0].topic(), group[0].partition()) not in revoked
        )
        self.retries.revoke(partitions)

    def _assign(self, client, partitions):
        if self.closing:
            return
        topic = f"appchi.{self.settings.environment}.alerts.changed"
        if (
            len(client.list_topics(topic, timeout=5).topics[topic].partitions)
            != self.control["changed_partitions"]
        ):
            raise unavailable("kafka_partition_topology_changed")
        fenced = []
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
                    fenced.append(p)
                offset = low
            p.offset = offset
        client.assign(partitions)
        for point in fenced:
            self.retries.fence(point)

    def turn(self):
        self.retries.resume_due()
        # Poll callbacks even while a bounded fetched batch is being drained, so
        # another partition's slow dependency cannot expire group membership.
        if self.pending:
            message = self.client.poll(0)
            messages = [message] if message is not None else []
        else:
            messages = self.client.consume(self.batch_size, timeout=0.1)
        for message in messages:
            if message.error():
                raise unavailable("changed_consume_failed")
            key = (message.topic(), message.partition())
            if key in self.retries.failed:
                continue
            group = next(
                (
                    g
                    for g in self.pending
                    if (g[0].topic(), g[0].partition()) == key and len(g) < self.batch_size
                ),
                None,
            )
            if group is None:
                self.pending.append([message])
            else:
                group.append(message)
        if not self.pending:
            return 0
        group = self.pending.popleft()
        try:
            if self.batch_handler:
                try:
                    count = self.batch_handler(self.db, self.settings, self.profile, group)
                except Exception:
                    if len(group) == 1:
                        raise
                    # A bad later record must not pin the partition before the
                    # actual fault. Resolve its healthy prefix without skipping.
                    self.handler(self.db, self.settings, self.profile, group[0])
                    count = 1
                if count is None:
                    count = len(group)
                if type(count) is not int or not 1 <= count <= len(group):
                    raise unavailable("changed_batch_progress_invalid")
            else:
                self.handler(self.db, self.settings, self.profile, group[0])
                count = 1
        except Exception:
            failed = group[0]
            self.retries.fail(failed)
            key = (failed.topic(), failed.partition())
            self.pending = deque(g for g in self.pending if (g[0].topic(), g[0].partition()) != key)
            with self.db.transaction() as conn:
                conn.execute(
                    """INSERT INTO kafka_pipeline_faults(consumer,topic,partition,input_offset,reason)
                    VALUES(%s,%s,%s,%s,'changed_processing_failed') ON CONFLICT DO NOTHING""",
                    (self.role, failed.topic(), failed.partition(), failed.offset()),
                )
            log.warning(
                "changed_partition_retry",
                extra={"consumer": self.role, "partition": failed.partition()},
            )
            return 0
        message = group[count - 1]
        self.client.commit(message=message, asynchronous=False)
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO kafka_consumer_positions(consumer,topic,partition,next_offset) VALUES(%s,%s,%s,%s)
                ON CONFLICT(consumer,topic,partition) DO UPDATE SET next_offset=greatest(kafka_consumer_positions.next_offset,EXCLUDED.next_offset),updated_at=clock_timestamp()""",
                (self.role, message.topic(), message.partition(), message.offset() + 1),
            )
        if count < len(group):
            # Preserve partition append order while rotating healthy partitions.
            remainder = group[count:]
            for queued in list(self.pending):
                if (queued[0].topic(), queued[0].partition()) == (
                    message.topic(),
                    message.partition(),
                ):
                    remainder.extend(queued)
                    self.pending.remove(queued)
            self.pending.append(remainder)
        return count

    def close(self):
        self.closing = True
        self.client.close()
