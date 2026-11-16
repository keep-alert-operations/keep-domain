"""Send log records to the Fluent Bit deployment (REV-74, observability 6).

Records queue in memory and a background thread posts them in batches to the path
named for their service, which is how Fluent Bit routes them to one index per
service. Shipping never blocks or fails the work being logged: an unreachable
Fluent Bit is retried with backoff, a full queue drops its oldest records from
shipping and counts them, and the stderr copy of every record remains.
"""

from collections import deque
from http.client import HTTPConnection, HTTPSConnection
import logging
from threading import Condition, Thread
from time import monotonic
from urllib.parse import urlsplit

from keep.observability.metrics import counter, gauge, histogram

RECORDS = counter(
    "keep_log_ship_records_total", "Log records sent to or dropped from shipping.", ("outcome",)
)
FAILURES = counter("keep_log_ship_failures_total", "Failed posts to Fluent Bit.")
SECONDS = histogram("keep_log_ship_request_seconds", "Duration of one post to Fluent Bit.")
QUEUE = gauge("keep_log_ship_queue_records", "Log records waiting to be shipped.")


# One post stays well under Fluent Bit's request limit (buffer_max_size), so a batch
# of whole-alert records is never refused for its size and then retried forever.
POST_BYTES = 1024 * 1024


def _posts(group, limit):
    """Split one service's records into posts of at most ``limit`` bytes each."""
    post, size = [], 0
    for item in group:
        length = len(item[1]) + 1
        if post and size + length > limit:
            yield post
            post, size = [], 0
        post.append(item)
        size += length
    if post:
        yield post


class ShipHandler(logging.Handler):
    def __init__(
        self,
        url,
        service,
        *,
        capacity=10000,
        batch=500,
        interval=1.0,
        timeout=2.0,
        backoff=5.0,
        idle=5.0,
    ):
        super().__init__()
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
            raise ValueError("KEEP_LOG_SHIP_URL must be an http(s) address without credentials")
        self._secure = parts.scheme == "https"
        self._host = parts.hostname
        self._port = parts.port or (443 if self._secure else 80)
        self._prefix = parts.path.rstrip("/")
        self.service = service
        self.capacity, self.batch, self.interval = capacity, batch, interval
        self.timeout, self.backoff = timeout, backoff
        # Fluent Bit drops a connection that stays silent for 10 seconds and logs an
        # error. Closing an idle one first avoids both that and a stale connection.
        self.idle = idle
        self._used = 0.0
        self._items = deque()
        self._ready = Condition()
        self._closing = False
        self._sending = False
        self._connection = None
        QUEUE.set_function(lambda: len(self._items))
        self._thread = Thread(target=self._run, name="keep-log-ship", daemon=True)
        self._thread.start()

    def emit(self, record):
        try:
            line = self.format(record).encode("utf-8")
            service = getattr(record, "keep_service", None) or self.service
            with self._ready:
                if self._closing:
                    return
                if len(self._items) >= self.capacity:
                    self._items.popleft()
                    RECORDS.labels("dropped").inc()
                self._items.append((service, line))
                if len(self._items) >= self.batch:
                    self._ready.notify()
        except Exception:
            self.handleError(record)

    def _run(self):
        delay = 0.0
        while True:
            with self._ready:
                # One post per interval, sooner only for a full batch, a flush or
                # shutdown; after a failure, wait out the backoff instead.
                if not self._closing and (delay or len(self._items) < self.batch):
                    self._ready.wait(delay or self.interval)
                items = [self._items.popleft() for _ in range(min(self.batch, len(self._items)))]
                closing = self._closing
                self._sending = bool(items)
            if not items:
                if closing:
                    return
                if self._connection is not None and monotonic() - self._used >= self.idle:
                    self._disconnect()
                continue
            unsent = self._send(items)
            with self._ready:
                self._sending = False
                if unsent:
                    if closing:
                        RECORDS.labels("dropped").inc(len(unsent))
                    else:
                        # Back to the front; over capacity, the oldest are dropped first.
                        self._items.extendleft(reversed(unsent))
                        while len(self._items) > self.capacity:
                            self._items.popleft()
                            RECORDS.labels("dropped").inc()
                self._ready.notify_all()
            if unsent and closing:
                return
            delay = min(self.backoff, max(0.5, delay * 2)) if unsent else 0.0

    def _send(self, items):
        """Post each service's records to its own path; return what was not accepted."""
        groups = {}
        for item in items:
            groups.setdefault(item[0], []).append(item)
        unsent = []
        posts = [
            (service, post) for service, items in groups.items() for post in _posts(items, POST_BYTES)
        ]
        for service, group in posts:
            body = b"[" + b",".join(line for _, line in group) + b"]"
            started = monotonic()
            try:
                self._post(f"{self._prefix}/keep.{service}", body)
                RECORDS.labels("sent").inc(len(group))
            except Exception:
                # Never logged: a record about shipping would itself be shipped.
                FAILURES.inc()
                self._disconnect()
                unsent.extend(group)
            finally:
                SECONDS.observe(monotonic() - started)
        return unsent

    def _post(self, path, body):
        """Post one body, once more on a fresh connection if a kept one had gone stale.

        A repeated post cannot duplicate records: Fluent Bit derives each record's
        Elasticsearch ID from its content.
        """
        for fresh in (False, True):
            kept = self._connection is not None
            try:
                connection = self._connect()
                connection.request(
                    "POST",
                    path,
                    body,
                    {"Content-Type": "application/json", "Connection": "keep-alive"},
                )
                response = connection.getresponse()
                response.read()
            except Exception:
                self._disconnect()
                if fresh or not kept:
                    raise
                continue
            if not 200 <= response.status < 300:
                raise OSError("rejected")
            self._used = monotonic()
            return

    def _connect(self):
        if self._connection is None:
            kind = HTTPSConnection if self._secure else HTTPConnection
            self._connection = kind(self._host, self._port, timeout=self.timeout)
        return self._connection

    def _disconnect(self):
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None

    def flush(self, timeout=2.0):
        """Wait, briefly, until everything queued so far has been sent."""
        deadline = monotonic() + timeout
        with self._ready:
            self._ready.notify_all()
            while (self._items or self._sending) and self._thread.is_alive():
                left = deadline - monotonic()
                if left <= 0:
                    break
                self._ready.wait(min(0.05, left))

    def close(self):
        self.flush()
        with self._ready:
            self._closing = True
            self._ready.notify_all()
        self._thread.join(self.timeout + 1)
        self._disconnect()
        super().close()
