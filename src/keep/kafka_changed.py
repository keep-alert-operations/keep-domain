"""Independent changed-event consumer groups. PostgreSQL stores proof, not work triggers."""

from collections import deque
from time import monotonic
from types import MappingProxyType
import logging

from keep.observability import Flow, log_event
from keep.observability.flow import seconds_since as seconds_since
from keep.observability.kafka import statistics_options
from keep.observability.metrics import gauge
from keep.shared.errors import unavailable

log = logging.getLogger(__name__)


def changed_flow(logger, consumer, message, envelope):
    """Begin the flow of one changed event in its consumer and record that it was read.

    The returned flow carries the event, alert and Kafka position on every later
    step the consumer writes for this change (observability 3).
    """
    alert = {"id": envelope.alert_id}
    if getattr(envelope, "native_version", None):
        alert["native_version"] = envelope.native_version
    flow = Flow(
        logger,
        alert=alert,
        consumer=consumer,
        changed_event_id=envelope.event_id,
        tenant_id=envelope.tenant_id,
        cause=getattr(envelope, "cause", None),
        partition=message.partition(),
        offset=message.offset(),
        projection_seq=getattr(envelope, "projection_seq", None),
    )
    flow.step(
        "alert_change_consumed",
        detail=True,
        delay_seconds=seconds_since(getattr(envelope, "recorded_at", None)),
    )
    return flow


HELD = gauge(
    "keep_kafka_partitions_held",
    "Partitions this process holds at one offset: retrying, or fenced until repair.",
    ("state",),
)


def _identifiers(message):
    """The changed event and alert that a failed input names, when it can be read."""
    try:
        from keep.event_models import ChangedEnvelope
        from keep.ingestion.native import parse_json

        envelope = ChangedEnvelope.model_validate(parse_json(message.value()))
    except Exception:
        return {}
    return {
        "changed_event_id": envelope.event_id,
        "alert_id": envelope.alert_id,
        "tenant_id": envelope.tenant_id,
    }

# Most inputs one fetch or one handler call may carry. A search hint becomes at
# most one document, so this matches the projection writer's bulk limit.
MAX_BATCH = 500


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
        self._count()

    def _count(self):
        fenced = sum(1 for _, deadline in self.failed.values() if deadline == float("inf"))
        HELD.labels("fenced").set(fenced)
        HELD.labels("retrying").set(len(self.failed) - fenced)

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
                self._count()

    def revoke(self, partitions):
        for point in partitions:
            self.failed.pop((point.topic, point.partition), None)
        self._count()

    def fence(self, point):
        # Retention loss needs an explicit repair/restart, not a timed retry.
        # Assignment uses the broker low offset but this partition is paused
        # before polling, and no group offset is advanced by the fence.
        self.client.pause([point])
        self.failed[(point.topic, point.partition)] = (point, float("inf"))
        self._count()


class ChangedConsumer:
    # Optional handler for several partitions' groups at once; see _turn_groups.
    groups_handler = None
    # Partitions a failed shared call included, each mapped to the last offset
    # of its prefix in that call. Such a partition runs alone until that offset
    # is handled, or it is fenced, revoked or lost. Replaced, never mutated.
    solo = MappingProxyType({})

    def __init__(
        self,
        db,
        settings,
        profile,
        role,
        handler,
        *,
        batch_handler=None,
        groups_handler=None,
        batch_size=50,
        commit_every=100,
        commit_interval=0.1,
    ):
        from confluent_kafka import Consumer
        from keep.service_clients import kafka_options

        self.db, self.settings, self.profile, self.role = db, settings, profile, role
        self.handler = handler
        self.batch_handler = batch_handler
        self.groups_handler = groups_handler
        self.batch_size = min(MAX_BATCH, max(1, batch_size))
        self.pending = deque()
        self.closing = False
        # Handled inputs whose PostgreSQL transactions committed but whose offsets
        # are not committed yet. Replay of these inputs is idempotent.
        self.commit_every, self.commit_interval = max(1, commit_every), commit_interval
        self.uncommitted, self.uncommitted_count, self.uncommitted_since = {}, 0, None
        with db.transaction() as conn:
            self.control = conn.execute(
                "SELECT * FROM kafka_pipeline_control WHERE singleton"
            ).fetchone()
            if not self.control["enabled"]:
                raise unavailable("kafka_cutover_required")
        self.client = Consumer(
            {
                **kafka_options(settings),
                **statistics_options(),
                "group.id": f"keep.{settings.environment}.{role}-v2",
                "enable.auto.commit": False,
                "enable.auto.offset.store": False,
                "isolation.level": "read_committed",
                "auto.offset.reset": "error",
            }
        )
        self.retries = PartitionRetries(self.client)
        self.client.subscribe(
            [f"keep.{settings.environment}.alerts.changed"],
            on_assign=self._assign,
            on_revoke=self._revoke,
            on_lost=self._lost,
        )

    def _revoke(self, client, partitions, *, lost=False):
        revoked = {(p.topic, p.partition) for p in partitions}
        # A revoking generation still owns its partitions: commit what it handled.
        # A lost (fenced) generation cannot commit; the next owner replays from the
        # committed offset. Neither carries offsets into a later assignment.
        if not lost:
            try:
                self.flush()
            except Exception:
                log.warning("changed_revoke_commit_failed consumer=%s", self.role)
        self._forget(revoked)
        self.solo = {key: offset for key, offset in self.solo.items() if key not in revoked}
        self.pending = deque(
            group
            for group in self.pending
            if (group[0].topic(), group[0].partition()) not in revoked
        )
        self.retries.revoke(partitions)

    @staticmethod
    def _key(group):
        return (group[0].topic(), group[0].partition())

    def _lost(self, client, partitions):
        self._revoke(client, partitions, lost=True)

    def _forget(self, keys):
        for key in keys:
            self.uncommitted.pop(key, None)
        if not self.uncommitted:
            self.uncommitted_count, self.uncommitted_since = 0, None

    def _handled(self, message, count, *, flush=True):
        self.uncommitted[(message.topic(), message.partition())] = message
        self.uncommitted_count += count
        if self.uncommitted_since is None:
            self.uncommitted_since = monotonic()
        if flush:
            self._flush_due()

    def _flush_due(self):
        if self.uncommitted and (
            self.uncommitted_count >= self.commit_every
            or monotonic() - self.uncommitted_since >= self.commit_interval
        ):
            self.flush()

    def flush(self):
        """Commit handled offsets, then record them in one PostgreSQL statement.

        Every handled input's PostgreSQL transaction has already committed, so a
        broker offset never runs ahead of durable state. The recorded positions are
        diagnostics and follow the broker commit.
        """
        if not self.uncommitted:
            return
        from confluent_kafka import TopicPartition

        handled = list(self.uncommitted.values())
        self.client.commit(
            offsets=[TopicPartition(m.topic(), m.partition(), m.offset() + 1) for m in handled],
            asynchronous=False,
        )
        self._forget(list(self.uncommitted))
        # One statement that never selects REPEATABLE READ: take the restore
        # guard inside this transaction instead of around it.
        with self.db.transaction(read_committed=True) as conn:
            conn.execute(
                """INSERT INTO kafka_consumer_positions(consumer,topic,partition,next_offset)
                SELECT %s,* FROM unnest(%s::text[],%s::integer[],%s::bigint[])
                ON CONFLICT(consumer,topic,partition) DO UPDATE SET next_offset=greatest(kafka_consumer_positions.next_offset,EXCLUDED.next_offset),updated_at=clock_timestamp()""",
                (
                    self.role,
                    [m.topic() for m in handled],
                    [m.partition() for m in handled],
                    [m.offset() + 1 for m in handled],
                ),
            )

    def _assign(self, client, partitions):
        if self.closing:
            return
        topic = f"keep.{self.settings.environment}.alerts.changed"
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
            self._flush_due()
            return 0
        total = 0
        if self.groups_handler:
            total, head_done = self._turn_groups()
            if head_done or not self.pending:
                return total
        return total + self._turn_head()

    def _turn_groups(self):
        """Handle the first pending group of every partition in one handler call.

        The handler receives one input prefix per partition, at most batch_size
        inputs in all, and returns how many leading inputs of each prefix are
        durably handled. Each partition advances only by its own count, after
        the call returned. A failed call or an unhandled head advances nothing
        here; the head then takes the single-partition path below, which
        isolates and fences a faulty input exactly as before.
        """
        # A partition a failed shared call included runs alone until every input
        # it had in that call is handled (see _advance), or it is fenced.
        if self._key(self.pending[0]) in self.solo:
            return 0, False
        chosen, seen, room = [], set(), self.batch_size
        for group in self.pending:
            key = self._key(group)
            if key in seen or key in self.solo:
                continue
            seen.add(key)
            chosen.append((group, group[:room]))
            room -= len(chosen[-1][1])
            if room <= 0:
                break
        if len(chosen) < 2:
            return 0, False
        prefixes = [prefix for _, prefix in chosen]
        try:
            counts = self.groups_handler(self.db, self.settings, self.profile, prefixes)
            if (
                not isinstance(counts, (list, tuple))
                or len(counts) != len(prefixes)
                or any(
                    type(count) is not int or not 0 <= count <= len(prefix)
                    for count, prefix in zip(counts, prefixes)
                )
            ):
                raise unavailable("changed_batch_progress_invalid")
        except Exception:
            log.warning("changed_groups_batch_failed consumer=%s", self.role)
            # One lasting fault would fail every shared call. The head runs alone
            # now; each other partition runs alone until every input it had in
            # this call is handled (see _advance).
            self.solo = {
                **self.solo,
                **{self._key(prefix): prefix[-1].offset() for _, prefix in chosen[1:]},
            }
            return 0, False
        total = 0
        for (group, _), count in zip(chosen, counts):
            if count:
                self.pending = deque(g for g in self.pending if g is not group)
                self._advance(group, count, flush=False)
                total += count
        # One broker commit then carries every advanced partition's own offset.
        self._flush_due()
        return total, counts[0] > 0

    def _turn_head(self):
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
        except Exception as error:
            failed = group[0]
            self.retries.fail(failed)
            key = (failed.topic(), failed.partition())
            self.solo = {k: offset for k, offset in self.solo.items() if k != key}
            self.pending = deque(g for g in self.pending if (g[0].topic(), g[0].partition()) != key)
            with self.db.transaction() as conn:
                conn.execute(
                    """INSERT INTO kafka_pipeline_faults(consumer,topic,partition,input_offset,reason)
                    VALUES(%s,%s,%s,%s,'changed_processing_failed') ON CONFLICT DO NOTHING""",
                    (self.role, failed.topic(), failed.partition(), failed.offset()),
                )
            # Class, controlled code and stack only: exception text can quote values.
            log_event(
                log,
                "changed_partition_retry",
                exc=error,
                consumer=self.role,
                partition=failed.partition(),
                offset=failed.offset(),
                **_identifiers(failed),
            )
            # The failed partition's handled prefix and other partitions' progress
            # must not wait behind the retry.
            self.flush()
            return 0
        self._advance(group, count)
        return count

    def _advance(self, group, count, *, flush=True):
        """Record a handled prefix of a removed group and requeue its remainder.

        A solo mark clears once the last offset the partition had in the failed
        shared call is handled, whichever path handled it. A partial batch or a
        one-record fallback short of that offset keeps the partition solo, so a
        fault inside the failed prefix cannot fail shared calls again.
        """
        message = group[count - 1]
        key = self._key(group)
        if key in self.solo and message.offset() >= self.solo[key]:
            self.solo = {k: offset for k, offset in self.solo.items() if k != key}
        self._handled(message, count, flush=flush)
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

    def close(self):
        self.closing = True
        try:
            self.flush()
        except Exception:
            # Unflushed inputs replay from the committed offset.
            log.warning("changed_close_commit_failed consumer=%s", self.role)
        finally:
            self.client.close()
