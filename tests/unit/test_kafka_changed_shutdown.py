"""librdkafka may invoke assignment callbacks while closing a consumer."""

from keep.kafka_changed import ChangedConsumer


def test_close_does_not_restart_assignment_or_retention_checks():
    consumer = ChangedConsumer.__new__(ChangedConsumer)
    consumer.closing = False

    class Client:
        def close(self):
            # No settings/database are installed: assignment must not inspect
            # topology or mutate retention diagnostics during shutdown.
            consumer._assign(self, [object()])

    consumer.uncommitted = {}
    consumer.client = Client()
    consumer.close()
    assert consumer.closing
