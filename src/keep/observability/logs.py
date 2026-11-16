"""Structured log records for every Keep process (REV-74, observability 2 to 5).

``configure_logging`` is called once by each entrypoint. ``log_event`` writes one
catalogued event. The Python-level message stays ``token key=value`` text, as the
code has always logged, and the formatter turns the record into one JSON object
with Elastic Common Schema names. Exception text is never written: it can carry
connection details, SQL and values (observability 4).
"""

from datetime import UTC, datetime
import json
import logging
import os
from pathlib import Path
import re
import socket
import sys
import threading
from time import monotonic
import traceback

from keep.observability.catalog import CATALOG, Event
from keep.observability.context import current
from keep.observability.fields import ALERT_FIELDS, DURATION, FIELDS, coerce
from keep.observability.metrics import LONG, SPAN, counter, histogram

# Tests set this: an unregistered event or field, or a missing required field, raises.
# In production the record is still written and the stray field is dropped.
STRICT = False

# Whether every step of an alert's flow is written, or only each service's outcome
# record (KEEP_LOG_ALERT_STEPS=outcome). Failures are written either way.
DETAIL = True

ECS_VERSION = "8.11.0"
SERVICES = {
    "product-api": "api",
    "ingestion-api": "ingestion",
    "private-ingestion": "ingestion",
    "source": "processor",
    "correlation": "correlation",
    "indexer": "indexer",
}
_LIBRARIES = (
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "httpx",
    "httpcore",
    "elasticsearch",
    "elastic_transport",
    "redis",
    "asyncio",
)
_TOKEN = re.compile(r"[a-z][a-z0-9_]*\Z")
_identity = {"service": "unknown", "role": None, "environment": None, "version": None, "node": None}
_log = logging.getLogger(__name__)

RECORDS = counter("keep_log_records_total", "Log records written, by level.", ("level",))
# Every catalogued event moves a metric of the same name (observability 7), so each
# flow and failure that is logged is also counted, without a second list to maintain.
EVENTS = counter(
    "keep_events_total",
    "Events, by name, outcome and the event's reason, cause or error code.",
    ("event", "outcome", "reason"),
)
EVENT_SECONDS = histogram(
    "keep_event_duration_seconds",
    "How long the work an event reports took.",
    ("event",),
    buckets=LONG,
)
EVENT_DELAY = histogram(
    "keep_event_delay_seconds",
    "Time from the earlier moment an event names (a receipt or a change) to the event.",
    ("event",),
    buckets=SPAN,
)
UNHANDLED = counter(
    "keep_process_unhandled_errors_total", "Exceptions that escaped every handler.", ("origin",)
)


def service_name():
    return _identity["service"]


def error_fields(error):
    """Class, controlled code, SQLSTATE and stack frames; never the message."""
    kind = type(error)
    fields = {"error_class": f"{kind.__module__}.{kind.__qualname__}"}
    code = getattr(error, "code", None)
    if isinstance(code, str) and _TOKEN.match(code):
        fields["error_code"] = code
    sqlstate = getattr(error, "sqlstate", None)
    if isinstance(sqlstate, str):
        fields["sqlstate"] = sqlstate
    frames = traceback.extract_tb(error.__traceback__)[-30:]
    if frames:
        fields["stack"] = "\n".join(
            f"{Path(frame.filename).name}:{frame.lineno} {frame.name}" for frame in frames
        )
    return fields


def _token_text(event, entry, fields):
    if entry.text:
        try:
            return entry.text % fields
        except (KeyError, TypeError, ValueError):
            if STRICT:
                raise
    return " ".join([event, *(f"{name}={_plain(value)}" for name, value in fields.items())])


def _plain(value):
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return value


def measure(event, outcome, fields, *, known=True):
    """Count one event and observe its timings. Requests have their own metrics."""
    if event.startswith("http_"):
        return
    name = event if known else "unregistered"
    result = fields.get("outcome") or outcome or "none"
    reason = fields.get("reason") or fields.get("cause") or fields.get("error_code") or ""
    EVENTS.labels(name, str(result), str(reason)).inc()
    seconds = fields.get(DURATION)
    if seconds is not None:
        EVENT_SECONDS.labels(name).observe(float(seconds))
    delay = fields.get("delay_seconds")
    if delay is not None:
        EVENT_DELAY.labels(name).observe(float(delay))


def outcome_of(entry, ok, level):
    """The record's outcome: fixed by the catalog, given by the caller, or a failure."""
    if ok is not None:
        return "success" if ok else "failure"
    if entry.outcome is None and level >= logging.WARNING:
        return "failure"
    return entry.outcome


def log_event(
    logger,
    event,
    /,
    *,
    level=None,
    ok=None,
    exc=None,
    alert=None,
    line=None,
    service=None,
    **fields,
):
    """Write one catalogued event.

    ``fields`` use the registry's short names. ``exc`` adds the error's class, code
    and stack. ``alert`` is the object built by ``alerts.alert_fields``. ``ok`` sets
    the outcome where the catalog does not fix it. ``line`` keeps an existing token
    line exactly; the structured record is built from the fields either way.
    ``service`` writes the record on behalf of another service (the browser), so it
    is shipped to that service's index.
    """
    entry = CATALOG.get(event)
    known = entry is not None
    if entry is None:
        if STRICT:
            raise KeyError(f"log event {event} is not registered")
        entry = Event(logging.INFO, event, "")
    use = entry.level if level is None else level
    explicit = {name: value for name, value in fields.items() if value is not None}
    if exc is not None:
        # Class and controlled code join the token line; the stack does not.
        failure = error_fields(exc)
        stack = failure.pop("stack", None)
        explicit = {**explicit, **{k: v for k, v in failure.items() if k not in explicit}}
    outcome = outcome_of(entry, ok, use)
    # Counted whatever the log level: the numbers do not depend on what is written.
    measure(event, outcome, explicit, known=known)
    if not logger.isEnabledFor(use):
        return
    text = line if line is not None else _token_text(event, entry, explicit)
    if exc is not None and stack:
        explicit["stack"] = stack
    if STRICT:
        unknown = [name for name in explicit if name not in FIELDS and name != DURATION]
        unknown += [f"alert.{name}" for name in (alert or {}) if name not in ALERT_FIELDS]
        present = {*explicit, *current(), *(("alert",) if alert else ())}
        missing = [name for name in entry.required if name not in present]
        if unknown or missing:
            raise KeyError(f"log event {event}: unregistered {unknown}, missing {missing}")
    # The text is the message itself, never a format string: no arguments are passed.
    logger.log(
        use,
        text,
        extra={
            "keep_event": event,
            "keep_fields": explicit,
            "keep_alert": alert or None,
            "keep_outcome": outcome,
            **({"keep_service": service} if service else {}),
        },
        stacklevel=2,
    )


class _Unset(dict):
    def __missing__(self, key):
        return "?"


def _nest(flat):
    document = {}
    for path, value in flat.items():
        node = document
        *parents, leaf = path.split(".")
        for part in parents:
            node = node.setdefault(part, {})
        node[leaf] = value
    return document


class EcsFormatter(logging.Formatter):
    """One JSON object per record, nested by Elastic Common Schema namespace."""

    def document(self, record):
        event = getattr(record, "keep_event", None)
        fields = {**current(), **(getattr(record, "keep_fields", None) or {})}
        alert = getattr(record, "keep_alert", None) or {}
        text = record.getMessage()
        flat = {
            "@timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "log.level": record.levelname.lower(),
            "log.logger": record.name,
            "ecs.version": ECS_VERSION,
            "service.name": getattr(record, "keep_service", None) or _identity["service"],
            "process.pid": record.process,
        }
        relayed = getattr(record, "keep_service", None) is not None
        for path, key in (
            ("service.version", "version"),
            ("service.environment", "environment"),
            ("service.node.name", "node"),
            ("keep.role", "role"),
        ):
            # A record relayed for another service (the browser) is not in this role.
            if _identity[key] and not (relayed and key == "role"):
                flat[path] = _identity[key]
        if event:
            entry = CATALOG.get(event)
            flat["event.action"] = event
            sentence = entry.message if entry else event
            flat["message"] = sentence.format_map(_Unset({**fields, **alert}))
        else:
            # A plain logging call: keep its token as the action when it has one.
            token = text.split(" ", 1)[0] if text else ""
            flat["event.action"] = token if _TOKEN.match(token) else "log"
            flat["message"] = text
            if record.exc_info and record.exc_info[1] is not None:
                fields = {**error_fields(record.exc_info[1]), **fields}
        outcome = getattr(record, "keep_outcome", None)
        if outcome is None and record.levelno >= logging.WARNING:
            outcome = "failure"
        if outcome:
            flat["event.outcome"] = outcome
        for name, value in fields.items():
            if name == DURATION:
                flat["event.duration"] = int(float(value) * 1_000_000_000)
                continue
            field = FIELDS.get(name)
            if field is not None:
                flat[field.path] = coerce(field.kind, value)
        for name, value in alert.items():
            field = ALERT_FIELDS.get(name)
            if field is not None:
                flat[field.path] = str(value)
        return _nest(flat)

    def format(self, record):
        # The console and the shipper format the same record: build its JSON once.
        encoded = getattr(record, "keep_json", None)
        if encoded is None:
            encoded = record.keep_json = json.dumps(
                self.document(record), ensure_ascii=False, separators=(",", ":")
            )
        return encoded


class TextFormatter(logging.Formatter):
    """The same events as ``event key=value`` lines for a local console."""

    def format(self, record):
        stamp = datetime.fromtimestamp(record.created, UTC).strftime("%H:%M:%S.%f")[:-3]
        bound = " ".join(
            f"{name}={value}"
            for name, value in current().items()
            if name not in (getattr(record, "keep_fields", None) or {})
        )
        return " ".join(
            part
            for part in (stamp, record.levelname.lower(), record.getMessage(), bound)
            if part
        )


class _Count(logging.Filter):
    def filter(self, record):
        RECORDS.labels(record.levelname.lower()).inc()
        return True


class _OneRecordPerFact(logging.Filter):
    """uvicorn repeats an unhandled request error that Keep has already recorded."""

    def filter(self, record):
        return not (
            record.name == "uvicorn.error"
            and str(record.msg).startswith("Exception in ASGI application")
        )


def _mark(handler):
    handler._keep = True
    return handler


def configure_logging(service, *, role=None, environ=None, stream=None):
    """Set up this process's logging once. Safe to call again; it replaces its handlers."""
    environ = os.environ if environ is None else environ
    _identity.update(
        service=service,
        role=role,
        environment=environ.get("KEEP_ENVIRONMENT", "development"),
        version=environ.get("KEEP_SERVICE_VERSION") or None,
        node=environ.get("HOSTNAME") or socket.gethostname(),
    )
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_keep", False):
            root.removeHandler(handler)
            handler.close()
    level = getattr(logging, environ.get("KEEP_LOG_LEVEL", "INFO").upper(), None)
    if not isinstance(level, int):
        level = logging.INFO
    root.setLevel(level)
    # "outcome" writes only each service's outcome record per alert, not every step.
    global DETAIL
    DETAIL = environ.get("KEEP_LOG_ALERT_STEPS", "all") != "outcome"
    console = _mark(logging.StreamHandler(stream or sys.stderr))
    console.setFormatter(
        TextFormatter() if environ.get("KEEP_LOG_FORMAT", "json") == "text" else EcsFormatter()
    )
    console.addFilter(_Count())
    console.addFilter(_OneRecordPerFact())
    root.addHandler(console)
    address = environ.get("KEEP_LOG_SHIP_URL")
    if address:
        from keep.observability.shipping import ShipHandler

        ship = _mark(ShipHandler(address, service))
        ship.setFormatter(EcsFormatter())
        ship.addFilter(_OneRecordPerFact())
        root.addHandler(ship)
    # Libraries write through the same formatter, at warning and above.
    for name in _LIBRARIES:
        library = logging.getLogger(name)
        library.handlers.clear()
        library.propagate = True
        library.setLevel(max(level, logging.WARNING))
    _install_hooks()


_hooks_installed = False


def _install_hooks():
    """Record anything that escapes every handler, then keep Python's own behavior."""
    global _hooks_installed
    if _hooks_installed:
        return
    _hooks_installed = True
    previous, previous_thread = sys.excepthook, threading.excepthook

    def process_hook(kind, error, trace):
        if not issubclass(kind, KeyboardInterrupt):
            _unhandled(error, "main")
        previous(kind, error, trace)

    def thread_hook(args):
        if args.exc_value is not None and not issubclass(args.exc_type, SystemExit):
            _unhandled(args.exc_value, "thread")
        previous_thread(args)

    sys.excepthook, threading.excepthook = process_hook, thread_hook


def _unhandled(error, origin):
    try:
        UNHANDLED.labels(origin).inc()
        log_event(_log, "process_unhandled_error", exc=error, origin=origin)
    except Exception:
        pass  # The original hook still reports the failure.


class Repeats:
    """Record a persisting condition when it starts and then at most once a minute.

    ``due(key)`` returns the number of occurrences since the last record when one
    should be written now, otherwise None (observability 5).
    """

    def __init__(self, seconds=60.0):
        self.seconds = seconds
        self._state = {}

    def due(self, key):
        now = monotonic()
        last, count = self._state.get(key, (None, 0))
        count += 1
        if last is None or now - last >= self.seconds:
            self._state[key] = (now, 0)
            return count
        self._state[key] = (last, count)
        return None

    def clear(self, key):
        self._state.pop(key, None)
