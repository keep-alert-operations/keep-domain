"""Optional post-commit hints. There is intentionally no durable dispatch queue."""

from contextvars import ContextVar
import logging
from uuid import UUID

from keep.ingestion.native import parse_json
from keep.observability import Flow, flow as alert_flow

pending = ContextVar("alert_notifications", default=None)
_publisher = None
_topic = None
log = logging.getLogger(__name__)


def configure(settings):
    global _publisher, _topic
    _publisher, _topic = None, None
    if settings.kafka_bootstrap:
        from confluent_kafka import Producer
        from keep.service_clients import kafka_options

        from keep.observability.kafka import statistics_options

        _publisher = Producer(
            {
                **kafka_options(settings),
                **statistics_options(),
                "acks": "all",
                "enable.idempotence": True,
                "delivery.timeout.ms": 1000,
                "request.timeout.ms": 1000,
                "linger.ms": 0,
            }
        )
        _topic = f"keep.{settings.environment}.alerts.changed"


def remember(envelope):
    batch = pending.get()
    if batch is not None:
        batch.append(envelope)


def publish_best_effort(batch):
    if not batch or _publisher is None:
        return
    # A step of the request or pass that made the changes, when there is one.
    flow = alert_flow.active() or Flow(log)
    try:
        sent = []
        for envelope in batch:
            body = parse_json(envelope)
            tenant = UUID(body["tenant_id"])
            _publisher.produce(_topic, key=tenant.bytes, value=envelope)
            sent.append(body)
        if _publisher.flush(0.3):
            flow.step("alert_notification_unconfirmed", count=len(sent))
            return
        for body in sent:
            flow.step(
                "alert_notification_published",
                detail=True,
                alert={"id": body["alert_id"]},
                changed_event_id=body["event_id"],
                cause=body.get("cause"),
                topic=_topic,
            )
    except Exception as error:
        flow.step(
            "alert_notification_failed",
            count=len(batch),
            error_class=f"{type(error).__module__}.{type(error).__qualname__}",
        )
