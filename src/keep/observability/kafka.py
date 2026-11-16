"""Kafka client numbers from librdkafka's own statistics (REV-74, observability 7).

The client reports lag, offsets, queue depth and broker state by itself every few
seconds; reading that costs no extra broker call. It is switched on only where a
metrics port is configured, so a process without metrics is unchanged.

Only a client that lives as long as its process and is polled regularly may take
these options: the pipeline consumers, the ingestion publisher and the Product API
notifier. A client created or discarded inside another client's callback (the
source processor's transactional producers, made and dropped during a rebalance)
crashes the process in the Kafka library if it carries a statistics callback.
"""

import json
import os
from time import monotonic

from keep.observability.metrics import counter, gauge

INTERVAL_MS = 5000

LAG = gauge(
    "keep_kafka_consumer_lag_messages",
    "Messages between this consumer's position and the end of the partition.",
    ("topic", "partition"),
)
COMMITTED = gauge(
    "keep_kafka_consumer_committed_offset",
    "The offset this consumer group has committed for the partition.",
    ("topic", "partition"),
)
END = gauge(
    "keep_kafka_partition_end_offset", "The partition's high watermark.", ("topic", "partition")
)
QUEUED = gauge(
    "keep_kafka_client_queue_messages",
    "Messages waiting in this process's Kafka clients, by client kind.",
    ("kind",),
)
BROKERS = gauge(
    "keep_kafka_brokers", "Brokers as this process's Kafka clients see them.", ("kind", "state")
)
FAILURES = counter(
    "keep_kafka_statistics_errors_total", "Client statistics that could not be read."
)

_queued = {}
_states = {"up", "down", "init", "connect", "auth", "other"}


def statistics_options(environ=None):
    """The client options that turn statistics on, or none when metrics are off."""
    environ = os.environ if environ is None else environ
    if not environ.get("KEEP_METRICS_PORT"):
        return {}
    return {"statistics.interval.ms": INTERVAL_MS, "stats_cb": record}


def record(text):
    """Set the gauges from one statistics report. Never raises into the client."""
    try:
        report = json.loads(text)
        kind = str(report.get("type", "client"))
        now = monotonic()
        # A process can hold several clients of one kind; a closed one stops reporting.
        _queued[(kind, report.get("name"))] = (int(report.get("msg_cnt", 0)), now)
        for key, (_, reported) in list(_queued.items()):
            if now - reported > 3 * INTERVAL_MS / 1000:
                del _queued[key]
        QUEUED.labels(kind).set(sum(count for (k, _), (count, _) in _queued.items() if k == kind))
        seen = dict.fromkeys(_states, 0)
        for broker in (report.get("brokers") or {}).values():
            if int(broker.get("nodeid", -1)) < 0:
                continue  # bootstrap entries, not brokers of the cluster
            state = str(broker.get("state", "")).lower()
            seen[state if state in _states else "other"] += 1
        for state, count in seen.items():
            BROKERS.labels(kind, state).set(count)
        if kind != "consumer":
            return
        for topic, detail in (report.get("topics") or {}).items():
            for partition, numbers in (detail.get("partitions") or {}).items():
                if int(partition) < 0:
                    continue
                lag = int(numbers.get("consumer_lag", -1))
                if lag < 0:
                    # A consumer whose offsets are committed by its producer's
                    # transaction (the source processor) reports no lag of its own:
                    # take the distance from its read position to the stable end.
                    if numbers.get("fetch_state") not in (None, "active"):
                        continue  # not a partition this consumer reads
                    position = int(numbers.get("app_offset", -1))
                    if position < 0:
                        # Nothing read since assignment yet: where it will fetch next.
                        position = int(numbers.get("next_offset", -1))
                    end = int(numbers.get("ls_offset", -1))
                    if end < 0:
                        end = int(numbers.get("hi_offset", -1))
                    if position < 0 or end < 0:
                        continue  # not a partition this consumer reads
                    lag = max(0, end - position)
                LAG.labels(topic, partition).set(lag)
                COMMITTED.labels(topic, partition).set(int(numbers.get("committed_offset", -1)))
                END.labels(topic, partition).set(int(numbers.get("hi_offset", -1)))
    except Exception:
        FAILURES.inc()
