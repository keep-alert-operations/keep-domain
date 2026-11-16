"""What the shared HTTP layer records for every request (REV-74, observability 2, 7, 8).

``keep.http`` calls these around each request. Every error response passes through
``keep.http.error_response``, so recording there covers every current and future
error code without touching the routes that raise them.
"""

from contextlib import contextmanager
import logging
from time import monotonic

from keep.observability.context import bind
from keep.observability.flow import Flow, active
from keep.observability.logs import SERVICES, Repeats, log_event
from keep.observability.metrics import LONG, counter, gauge, histogram
from keep.observability.sli import classify, outcome

log = logging.getLogger("keep.http")

_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
# Route parameters that are resource identifiers and registered log fields.
_IDENTIFIERS = {
    "tenant_id": "tenant_id",
    "alert_id": "alert_id",
    "incident_id": "incident_id",
    "operator_id": "operator_id",
    "rule_id": "rule_id",
    "window_id": "window_id",
    "preset_id": "preset_id",
    "dashboard_id": "dashboard_id",
}

REQUESTS = counter(
    "keep_http_requests_total", "HTTP requests.", ("service", "route", "method", "status")
)
SECONDS = histogram(
    "keep_http_request_seconds",
    "Time to produce the response.",
    ("service", "route", "method"),
    buckets=LONG,
)
ERRORS = counter(
    "keep_http_errors_total", "Error responses, by error code.", ("service", "route", "code")
)
IN_FLIGHT = gauge("keep_http_requests_in_flight", "Requests being handled.", ("service",))
BODY = histogram(
    "keep_http_request_body_bytes",
    "Request body size.",
    ("service", "route"),
    buckets=(256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304),
)
UNHANDLED = counter(
    "keep_http_unhandled_errors_total",
    "Requests that failed with an unexpected exception.",
    ("service", "route"),
)
CLOSED = counter(
    "keep_http_client_disconnects_total",
    "Requests whose caller disconnected before the response.",
    ("service", "route"),
)
SLI = counter(
    "keep_sli_requests_total",
    "Requests by service level class and outcome (reliability 3).",
    ("sli", "outcome", "reason"),
)
SLI_SECONDS = histogram(
    "keep_sli_latency_seconds", "Latency of good requests, by service level class.", ("sli",)
)


FAILURES = counter(
    "keep_instrumentation_errors_total",
    "Failures inside request instrumentation; the request itself is unaffected.",
    ("origin",),
)


def _never_fails(default=None):
    """Instrumentation must not fail the request it describes; tests still see the bug."""

    def wrap(function):
        def guarded(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception:
                from keep.observability import logs

                if logs.STRICT:
                    raise
                FAILURES.labels(function.__name__).inc()
                return default() if callable(default) else default

        guarded.__name__ = function.__name__
        guarded.__doc__ = function.__doc__
        return guarded

    return wrap


def service_of(request):
    settings = getattr(request.app.state, "settings", None)
    return SERVICES.get(getattr(settings, "role", None), "unknown")


def route_of(request):
    return getattr(request.scope.get("route"), "path", None) or "unmatched"


# A successful read repeated by the same user is written once a minute with a count
# (observability 5): the UI refreshes some views every second or two.
REPEATED_READS = Repeats(60.0)
SLOW_SECONDS = 1.0
# What the UI asks again and again by itself: reads and searches (the count batch is
# a POST), and the session check.
_REFRESHED_CLASSES = frozenset({"read", "search"})
_REFRESHED_ROUTES = frozenset({"/auth/session"})
_REPEAT_KEYS = 20000


@contextmanager
def bound(request):
    """Bind the request's identity for every record written while it is handled.

    The request is also one flow: a change it makes to an alert is noted by the code
    that makes it and written, with this request's ID, once its transaction commits.
    """
    with bind(request_id=request.state.request_id), Flow(log):
        yield


@_never_fails()
def actor(request, principal_id, tenant=None):
    """The authenticated user, on the request's own record and on its steps.

    Authorization also runs for callers that are not an HTTP request in flight (a
    live stream re-checking its grant); those have no record to add to.
    """
    if getattr(request, "state", None) is not None:
        annotate(request, principal_id=principal_id)
    flow = active()
    if flow is None:
        return
    params = getattr(request, "path_params", None) or {}
    identifiers = {
        field: value
        for name, field in _IDENTIFIERS.items()
        if name != "alert_id" and (value := params.get(name)) is not None
    }
    if tenant is not None:
        identifiers["tenant_id"] = tenant
    flow.know(principal_id=principal_id, **identifiers)


@_never_fails(lambda: ("unknown", monotonic()))
def started(request):
    service = service_of(request)
    IN_FLIGHT.labels(service).inc()
    return service, monotonic()


@_never_fails()
def unhandled(request, error):
    """An exception no handler claimed; it is answered 500 ``internal_error``."""
    request.state.error_code = "internal_error"
    request.state.unhandled = True
    UNHANDLED.labels(service_of(request), route_of(request)).inc()
    log_event(
        log,
        "http_unhandled_error",
        exc=error,
        request_id=request.state.request_id,
        method=request.method,
        route=route_of(request),
    )


@_never_fails()
def finished(request, observed, status):
    """Record one finished request: counters, service level outcome and its record."""
    service, begun = observed
    IN_FLIGHT.labels(service).dec()
    seconds = monotonic() - begun
    route = route_of(request)
    method = request.method if request.method in _METHODS else "OTHER"
    state = request.state
    if status is None and getattr(state, "unhandled", False):
        status = 500
    code = getattr(state, "error_code", None)
    closed = status is None
    sli = classify(method, route)
    result, reason = outcome(sli, status, code, closed=closed)
    override = getattr(state, "sli_outcome", None)
    if override is not None and sli not in ("health", "rum", "unmatched"):
        result, reason = override
    SLI.labels(sli, result, reason).inc()
    if result == "good":
        SLI_SECONDS.labels(sli).observe(seconds)
    body = getattr(state, "body_bytes", None)
    if body is not None:
        BODY.labels(service, route).observe(body)
    identifiers = {
        field: value
        for name, field in _IDENTIFIERS.items()
        if (value := request.path_params.get(name)) is not None
    }
    if closed:
        CLOSED.labels(service, route).inc()
        log_event(
            log,
            "http_client_closed",
            request_id=state.request_id,
            method=method,
            route=route,
            duration=seconds,
            **identifiers,
        )
        return
    REQUESTS.labels(service, route, method, str(status)).inc()
    SECONDS.labels(service, route, method).observe(seconds)
    if code:
        ERRORS.labels(service, route, code).inc()
    if sli == "health" and status < 400:
        return  # A passing probe is not an event (observability 5).
    known = getattr(state, "log_fields", {})
    repeats = None
    refreshed = sli in _REFRESHED_CLASSES or route in _REFRESHED_ROUTES
    if refreshed and status < 400 and seconds < SLOW_SECONDS:
        if len(REPEATED_READS._state) > _REPEAT_KEYS:
            REPEATED_READS._state.clear()
        key = (known.get("principal_id"), route, tuple(sorted(identifiers.items())))
        seen = REPEATED_READS.due(key)
        if seen is None:
            return  # Counted in the metrics; written with the next record of this read.
        repeats = seen - 1 or None
    log_event(
        log,
        "http_request",
        level=logging.WARNING if status >= 500 else None,
        ok=status < 400,
        request_id=state.request_id,
        method=method,
        route=route,
        status=status,
        error_code=code,
        duration=seconds,
        body_bytes=body,
        sli=sli,
        repeats=repeats,
        **{**identifiers, **known},
    )


def annotate(request, **fields):
    """Add fields a handler learned (the principal, say) to the request's own record."""
    known = getattr(request.state, "log_fields", None)
    if known is None:
        known = request.state.log_fields = {}
    known.update({name: value for name, value in fields.items() if value is not None})
