"""Optional post-commit hints. There is intentionally no durable dispatch queue."""

from contextvars import ContextVar
import logging
from uuid import UUID

from appchi.ingestion.native import parse_json

pending = ContextVar("alert_notifications", default=None)
_publisher = None
_topic = None
log = logging.getLogger(__name__)


def configure(settings):
    global _publisher, _topic
    _publisher, _topic = None, None
    if settings.kafka_bootstrap:
        from confluent_kafka import Producer
        from appchi.service_clients import kafka_options

        _publisher = Producer(
            {
                **kafka_options(settings),
                "acks": "all",
                "enable.idempotence": True,
                "delivery.timeout.ms": 1000,
                "request.timeout.ms": 1000,
                "linger.ms": 0,
            }
        )
        _topic = f"appchi.{settings.environment}.alerts.changed"


def remember(envelope):
    batch = pending.get()
    if batch is not None:
        batch.append(envelope)


def publish_best_effort(batch):
    if not batch or _publisher is None:
        return
    try:
        for envelope in batch:
            tenant = UUID(parse_json(envelope)["tenant_id"])
            _publisher.produce(_topic, key=tenant.bytes, value=envelope)
        if _publisher.flush(0.3):
            log.warning("alert_notification_unconfirmed")
    except Exception:
        log.warning("alert_notification_failed")
