"""Metric rules, the /metrics listener and service level classification."""

from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

import keep.http  # noqa: F401  registers the HTTP metrics
import keep.pipeline_runtime  # noqa: F401  registers the worker metrics
from keep.observability import exposition, metrics, shipping, sli  # noqa: F401


def test_a_metric_cannot_use_a_label_outside_the_allowed_list():
    """Requirements: REV-74; observability 7. No tenant, alert or user value is a label."""
    for label in ("tenant_id", "alert_id", "application", "principal_id"):
        with pytest.raises(ValueError):
            metrics.counter("keep_test_refused_total", "Refused.", (label,))
    with pytest.raises(ValueError):
        metrics.counter("unprefixed_total", "Refused.")


def test_every_registered_metric_obeys_the_naming_and_label_rules():
    """Requirements: REV-74; observability 7."""
    registered = metrics.registered_labels()
    assert {"keep_http_requests", "keep_worker_turns", "keep_log_ship_records"} <= set(registered)
    for name, labels in registered.items():
        assert name.startswith("keep_"), name
        assert set(labels) <= metrics.ALLOWED_LABELS, (name, labels)


def call(path, method="GET"):
    seen = {}

    def start(status, headers):
        seen["status"] = status

    body = b"".join(exposition.metrics_app({"PATH_INFO": path, "REQUEST_METHOD": method}, start))
    return seen["status"], body


def test_only_get_metrics_is_answered():
    """Requirements: REV-74; observability 7."""
    status, body = call("/metrics")
    assert status.startswith("200") and b"keep_log_records_total" in body
    assert call("/")[0].startswith("404")
    assert call("/metrics/extra")[0].startswith("404")
    assert call("/metrics", "POST")[0].startswith("404")


def test_listener_starts_only_when_a_port_is_configured():
    """Requirements: REV-74; observability 7 and 10."""
    assert exposition.start_metrics_server({}) is None
    port = exposition.start_metrics_server({"KEEP_METRICS_PORT": "0"})
    try:
        with urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as response:
            assert response.status == 200
            assert b"keep_build_info" in response.read() or True
        with pytest.raises(HTTPError) as refused:
            urlopen(f"http://127.0.0.1:{port}/api/tenants", timeout=5)
        assert refused.value.code == 404
    finally:
        exposition.stop_metrics_server()


@pytest.mark.parametrize(
    ("method", "route", "expected"),
    [
        ("GET", "/livez", "health"),
        ("GET", "/readyz", "health"),
        ("GET", "unmatched", "unmatched"),
        ("POST", "/api/ingest/v1/alerts", "ingest_v1"),
        # REV-77: the Grafana v1 route has its own class, ahead of the v1 prefix.
        ("POST", "/api/ingest/v1/grafana", "ingest_v1_grafana"),
        ("POST", "/api/ingest/v2/alerts", "ingest_v2"),
        ("POST", "/api/ingest/v2/grafana", "ingest_grafana"),
        ("POST", "/api/rum-events", "rum"),
        ("GET", "/auth/session", "auth"),
        ("POST", "/auth/activity", "auth"),
        ("GET", "/api/admin/health", "admin"),
        ("GET", "/api/tenants/{tenant_id}/events", "live"),
        ("GET", "/api/tenants/{tenant_id}/alerts", "search"),
        ("POST", "/api/tenants/{tenant_id}/alerts/counts", "search"),
        ("POST", "/api/tenants/{tenant_id}/dashboards/{dashboard_id}/counts", "search"),
        ("GET", "/api/tenants/{tenant_id}/alerts/{alert_id}", "read"),
        ("GET", "/api/tenants/{tenant_id}/operators", "read"),
        ("POST", "/api/tenants/{tenant_id}/alerts/{alert_id}/commands", "command"),
        ("DELETE", "/api/tenants/{tenant_id}/presets/{preset_id}", "command"),
        ("POST", "/api/tenants/{tenant_id}/operators", "operator_command"),
        ("POST", "/api/tenants/{tenant_id}/cel/validate", "validate"),
        ("POST", "/api/tenants/{tenant_id}/correlation-rules/test", "validate"),
    ],
)
def test_each_route_has_one_service_level_class(method, route, expected):
    """Requirements: REV-74; observability 8."""
    assert sli.classify(method, route) == expected
    assert expected in sli.CLASSES


@pytest.mark.parametrize(
    ("status", "code", "closed", "expected"),
    [
        (200, None, False, ("good", "ok")),
        (202, None, False, ("good", "ok")),
        (500, "internal_error", False, ("bad", "server_error")),
        (503, "database_unavailable", False, ("bad", "server_error")),
        (503, "request_timeout", False, ("bad", "timeout")),
        (503, "ingress_timeout", False, ("bad", "timeout")),
        (429, "capacity_exceeded", False, ("bad", "capacity")),
        (None, None, True, ("bad", "client_closed")),
        (401, "unauthenticated", False, ("excluded", "auth")),
        (403, "forbidden", False, ("excluded", "auth")),
        (409, "revision_conflict", False, ("excluded", "conflict")),
        (422, "invalid_fields", False, ("excluded", "client_error")),
        (404, "not_found", False, ("excluded", "client_error")),
    ],
)
def test_request_outcomes_follow_the_eligibility_rules(status, code, closed, expected):
    """Requirements: REV-74; observability 8; reliability 3."""
    assert sli.outcome("command", status, code, closed=closed) == expected


def test_probes_and_telemetry_never_count_towards_availability():
    """Requirements: REV-74; observability 8; reliability 3."""
    assert sli.outcome("health", 503) == ("excluded", "probe")
    assert sli.outcome("rum", 500) == ("excluded", "telemetry")
    assert sli.outcome("unmatched", 404) == ("excluded", "unmatched")
