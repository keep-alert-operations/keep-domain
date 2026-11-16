"""Service level classification of HTTP requests (REV-74, observability 8).

Every registered route has exactly one class, and each request's outcome is good,
bad or excluded under reliability 3. Recording rules over these counters give the
availability and latency indicators of reliability 2 to 5.
"""

CLASSES = (
    "ingest_v1",
    "ingest_v2",
    "ingest_grafana",
    "read",
    "command",
    "search",
    "operator_command",
    "validate",
    "auth",
    "live",
    "rum",
    "admin",
    "health",
    "unmatched",
)

# Feed, list, search and count requests (reliability 5: two seconds).
_SEARCH = {
    ("GET", "/api/tenants/{tenant_id}/alerts"),
    ("POST", "/api/tenants/{tenant_id}/alerts/groups"),
    ("POST", "/api/tenants/{tenant_id}/alerts/counts"),
    ("POST", "/api/tenants/{tenant_id}/alerts/snapshot/close"),
    ("POST", "/api/tenants/{tenant_id}/dashboards/{dashboard_id}/counts"),
    ("POST", "/api/tenants/{tenant_id}/dashboards/preview"),
    ("POST", "/api/tenants/{tenant_id}/presets/preview"),
    ("POST", "/api/tenants/{tenant_id}/presets/preview/groups"),
}
# Never counted in an availability indicator, whatever the status.
_UNCOUNTED = {"health": "probe", "rum": "telemetry", "unmatched": "unmatched"}
_TIMEOUTS = {"request_timeout", "ingress_timeout"}


def classify(method, route):
    """The class of one request, from its method and route template."""
    if route in ("/livez", "/readyz"):
        return "health"
    if not route or route == "unmatched":
        return "unmatched"
    if route.startswith("/api/ingest/v1/"):
        return "ingest_v1"
    if route.startswith("/api/ingest/v2/grafana"):
        return "ingest_grafana"
    if route.startswith("/api/ingest/v2/"):
        return "ingest_v2"
    if route == "/api/rum-events":
        return "rum"
    if route.startswith("/auth/"):
        return "auth"
    if route.startswith("/api/admin/"):
        return "admin"
    if route == "/api/tenants/{tenant_id}/events":
        return "live"
    if (method, route) in _SEARCH:
        return "search"
    if method in ("GET", "HEAD"):
        return "read"
    # Dry runs commit nothing and have no selected objective; reported on their own.
    if route.rsplit("/", 1)[-1] in ("validate", "test"):
        return "validate"
    if "/operators" in route:
        return "operator_command"
    return "command"


def outcome(sli, status, code=None, *, closed=False):
    """(good | bad | excluded, reason) for one finished request."""
    if sli in _UNCOUNTED:
        return "excluded", _UNCOUNTED[sli]
    if closed or status is None:
        # A connection lost after full receipt is a service failure.
        return "bad", "client_closed"
    if status >= 500:
        return "bad", "timeout" if code in _TIMEOUTS else "server_error"
    if status == 429:
        return "bad", "capacity"
    if status >= 400:
        if status in (401, 403):
            return "excluded", "auth"
        if status == 409:
            return "excluded", "conflict"
        return "excluded", "client_error"
    return "good", "ok"
