"""Shipping log records to the Fluent Bit deployment without ever blocking the work."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import socket
from threading import Thread
from time import monotonic, sleep

import pytest

from keep.observability import log_event, logs
from keep.observability.shipping import FAILURES, RECORDS, ShipHandler


class Collector:
    """A stand-in for Fluent Bit's HTTP input: remembers each post's path and records.

    ``idle`` makes it keep connections open and drop one that stays silent that long,
    as Fluent Bit does after 10 seconds.
    """

    def __init__(self, statuses=(), idle=None):
        self.posts, statuses = [], list(statuses)
        collector = self

        class Handler(BaseHTTPRequestHandler):
            if idle:
                protocol_version = "HTTP/1.1"
                timeout = idle

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                status = statuses.pop(0) if statuses else 201
                if status < 300:
                    collector.posts.append((self.path, json.loads(body)))
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def collector():
    target = Collector()
    yield target
    target.close()


def shipping(url, **options):
    handler = ShipHandler(url, "processor", interval=0.05, backoff=0.1, **options)
    handler.setFormatter(logs.EcsFormatter())
    logger = logging.getLogger("keep.test.shipping")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger, handler


def dropped():
    return RECORDS.labels("dropped")._value.get()


def test_records_post_as_batches_to_the_path_of_their_service(collector):
    """Requirements: REV-74; observability 6."""
    logger, handler = shipping(collector.url)
    try:
        for state in ("ready", "not_ready"):
            log_event(logger, "worker_ready_changed", role="source", state=state)
        logger.info("rum_event", extra={"keep_service": "browser"})
        handler.flush()
    finally:
        logger.removeHandler(handler)
        handler.close()
    by_path = {}
    for path, records in collector.posts:
        by_path.setdefault(path, []).extend(records)
    assert set(by_path) == {"/keep.processor", "/keep.browser"}
    assert [record["keep"]["state"] for record in by_path["/keep.processor"]] == [
        "ready",
        "not_ready",
    ]
    assert by_path["/keep.browser"][0]["service"]["name"] == "browser"
    assert "role" not in by_path["/keep.browser"][0].get("keep", {})


def test_unreachable_fluent_bit_never_blocks_and_drops_only_the_oldest():
    """Requirements: REV-74; observability 6. Shipping never fails the logged work."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    logger, handler = shipping(f"http://127.0.0.1:{closed_port}", capacity=3, timeout=0.2)
    before, failures = dropped(), FAILURES._value.get()
    try:
        started = monotonic()
        for attempt in range(8):
            log_event(logger, "worker_ready_changed", role="source", state=f"s{attempt}")
        assert monotonic() - started < 0.5
        handler.flush(0.5)
        assert len(handler._items) <= 3
        assert dropped() - before >= 5
        assert FAILURES._value.get() > failures
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_a_failed_post_is_retried_and_arrives_once():
    """Requirements: REV-74; observability 6."""
    target = Collector(statuses=[503])
    logger, handler = shipping(target.url)
    try:
        log_event(logger, "worker_ready_changed", role="source", state="ready")
        handler.flush(3)
    finally:
        logger.removeHandler(handler)
        handler.close()
        target.close()
    assert [len(records) for _, records in target.posts] == [1]


def test_a_connection_fluent_bit_dropped_while_idle_costs_no_failure():
    """Requirements: REV-74; observability 6. The stale connection is replaced at once."""
    target = Collector(idle=0.2)
    logger, handler = shipping(target.url)
    failures = FAILURES._value.get()
    try:
        log_event(logger, "worker_ready_changed", role="source", state="ready")
        handler.flush()
        sleep(0.6)  # the collector has dropped the kept connection
        log_event(logger, "worker_ready_changed", role="source", state="not_ready")
        handler.flush()
    finally:
        logger.removeHandler(handler)
        handler.close()
        target.close()
    states = [record["keep"]["state"] for _, records in target.posts for record in records]
    assert states == ["ready", "not_ready"]
    assert FAILURES._value.get() == failures


def test_an_idle_connection_is_closed_before_fluent_bit_drops_it(collector):
    """Requirements: REV-74; observability 6."""
    logger, handler = shipping(collector.url, idle=0.1)
    try:
        log_event(logger, "worker_ready_changed", role="source", state="ready")
        handler.flush()
        deadline = monotonic() + 2
        while handler._connection is not None and monotonic() < deadline:
            sleep(0.05)
        assert handler._connection is None
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_a_large_batch_is_split_into_posts_fluent_bit_accepts(collector, monkeypatch):
    """Requirements: REV-74; observability 6. No post is refused for its size."""
    from keep.observability import shipping as module

    monkeypatch.setattr(module, "POST_BYTES", 2000)
    logger, handler = shipping(collector.url)
    try:
        for attempt in range(12):
            log_event(logger, "worker_ready_changed", role="source", state=f"state-{attempt}")
        handler.flush()
    finally:
        logger.removeHandler(handler)
        handler.close()
    sizes = [len(json.dumps(records)) for _, records in collector.posts]
    assert len(collector.posts) > 1 and max(sizes) <= 2400
    states = [record["keep"]["state"] for _, records in collector.posts for record in records]
    assert states == [f"state-{attempt}" for attempt in range(12)]


@pytest.mark.parametrize(
    "address", ["ftp://fluent-bit:9880", "http://user:secret@fluent-bit:9880", "fluent-bit"]
)
def test_address_must_be_plain_http_without_credentials(address):
    """Requirements: REV-74; observability 4 and 6."""
    with pytest.raises(ValueError):
        ShipHandler(address, "processor")
