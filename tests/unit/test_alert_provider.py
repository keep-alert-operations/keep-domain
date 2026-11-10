from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4

import pytest

from keep.alerts.lifecycle import apply_source, delivery_provider
from keep.alerts.presentation import present_alert
from keep.cel import compile_expression
from keep.cel.catalog import CORRELATION_FIELDS, FIELDS, RULE_FIELDS, alert_provider
from keep.configuration.models import COLUMNS, GROUPABLE, SORTABLE
from keep.ingestion.native import identity
from keep.maintenance.processing import _snapshot
from keep.search.projection import Projection, build_document, index_mapping
from keep.serialization import wire

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
OPERATOR = uuid4()
GRAFANA = "keep-grafana-v1"
RULE = "https://grafana.example.org/alerting/grafana/cpu-rule/view?orgId=1"


def v2(**extra):
    return {
        "application": "pay",
        "component": "api",
        "message": "Checkout failing",
        "severity": "critical",
        "status": "firing",
        "site": "dc1",
        "impact": "Orders fail",
        "runbook_url": "https://example.org/runbook",
        "name": "High CPU",
        "time_created": "31-10-2026 11:59:00",
        **extra,
    }


def member(**extra):
    """A retained Grafana member; only its generatorURL matters here."""
    return json.dumps({"status": "firing", "labels": {}, "annotations": {}, **extra}).encode()


def item(payload, version="v2", adapter=None, raw=b"{}", when=NOW):
    return {
        "payload": payload,
        "received_at": when,
        "version": version,
        "tenant_id": uuid4(),
        "id": uuid4(),
        "key_field": identity(payload, version, OPERATOR)[0],
        "operator_id": OPERATOR,
        "adapter_version": adapter,
        "raw_json": raw,
    }


def created(payload, version="v2", adapter=None, raw=b"{}"):
    return apply_source(None, item(payload, version, adapter, raw))[0]


def test_native_deliveries_are_api_and_grafana_keeps_its_rule_url(v1):
    """Requirements: alert operations 3; operator operations 18 (REV-55)."""
    legacy = created(v1, "v1")
    assert (legacy["provider"], legacy["alert_rule_url"]) == ("api", None)
    native = created(v2())
    assert (native["provider"], native["alert_rule_url"]) == ("api", None)
    grafana = created(v2(), adapter=GRAFANA, raw=member(generatorURL=RULE))
    assert (grafana["provider"], grafana["alert_rule_url"]) == ("grafana", RULE)
    # An invalid or missing generatorURL leaves no rule URL; the alert still exists.
    for raw in (member(generatorURL="javascript:alert(1)"), member(), None):
        assert delivery_provider({"adapter_version": GRAFANA, "raw_json": raw}) == (
            "grafana",
            None,
        )
    # Database rows hand bytea over as memoryview.
    assert delivery_provider(
        {"adapter_version": GRAFANA, "raw_json": memoryview(member(generatorURL=RULE))}
    ) == ("grafana", RULE)


def test_provider_follows_the_latest_delivery_outside_identity_and_revision():
    """Requirements: alert operations 3, 5, 7 (REV-55)."""
    payload = v2()
    grafana = created(payload, adapter=GRAFANA, raw=member(generatorURL=RULE))
    later = item(payload, when=NOW + timedelta(minutes=1))
    assert later["key_field"] == grafana["key_field"]
    updated, changed = apply_source(grafana, later)
    assert (updated["provider"], updated["alert_rule_url"]) == ("api", None)
    # Only the provider changed, so the semantic revision stays and the
    # projection version still advances for search.
    assert not changed and updated["revision"] == grafana["revision"]
    assert updated["projection_version"] == grafana["projection_version"] + 1
    back, _ = apply_source(
        updated,
        item(payload, adapter=GRAFANA, raw=member(generatorURL=RULE + "&x=1"), when=NOW),
    )
    assert (back["provider"], back["alert_rule_url"]) == ("grafana", RULE + "&x=1")


def test_rows_without_a_provider_read_as_api_for_v1_and_none_for_v2(v1):
    """Requirements: alert operations 3 (REV-55)."""
    legacy_v1 = {k: v for k, v in created(v1, "v1").items() if k != "provider"}
    legacy_v2 = {k: v for k, v in created(v2()).items() if k != "provider"}
    assert alert_provider(legacy_v1) == "api"
    assert alert_provider(legacy_v2) is None
    assert alert_provider(created(v2(), adapter=GRAFANA)) == "grafana"
    assert present_alert(legacy_v1)["provider"] == "api"
    assert present_alert(legacy_v2)["provider"] is None
    assert present_alert(legacy_v2)["alert_rule_url"] is None


def test_catalog_offers_provider_to_feed_search_only():
    """Requirements: alert operations 3; preset operations 4 (REV-55)."""
    assert FIELDS["provider"].kind == "enum" and FIELDS["provider"].nullable
    assert FIELDS["provider"].values == ("api", "grafana")
    assert FIELDS["alert_rule_url"].kind == "string" and FIELDS["alert_rule_url"].nullable
    for field in ("provider", "alert_rule_url"):
        assert field not in RULE_FIELDS and field not in CORRELATION_FIELDS
        assert field in COLUMNS and field not in SORTABLE and field not in GROUPABLE
    mapping = index_mapping()["properties"]
    assert mapping["provider"]["type"] == "keyword"
    assert mapping["alert_rule_url"] == mapping["runbook_url"]
    assert mapping["missing_provider"] == mapping["missing_alert_rule_url"] == {"type": "boolean"}
    # Rule profiles reject the new fields.
    with pytest.raises(Exception):
        compile_expression('provider == "grafana"', rule=True)


def test_cel_provider_reads_the_resolved_provider(v1):
    """Requirements: alert operations 3, 4 (REV-55)."""
    grafana = created(v2(), adapter=GRAFANA, raw=member(generatorURL=RULE))
    assert compile_expression('provider == "grafana"').evaluate(grafana, NOW)
    assert compile_expression(f'alert_rule_url == "{RULE}"').evaluate(grafana, NOW)
    legacy_v1 = {k: v for k, v in created(v1, "v1").items() if k != "provider"}
    assert compile_expression('provider == "api"').evaluate(legacy_v1, NOW)
    assert compile_expression("alert_rule_url == null").evaluate(legacy_v1, NOW)
    legacy_v2 = {k: v for k, v in created(v2()).items() if k != "provider"}
    assert compile_expression("provider == null").evaluate(legacy_v2, NOW)


def test_maintenance_proof_is_unchanged_by_the_provider(v1):
    """Requirements: maintenance 6; alert operations 3 (REV-55)."""
    grafana = created(v2(), adapter=GRAFANA, raw=member(generatorURL=RULE))
    native = dict(grafana, provider="api", alert_rule_url=None)
    assert "provider" not in _snapshot(grafana)
    assert "alert_rule_url" not in _snapshot(grafana)
    assert _snapshot(grafana) == _snapshot(native)


def document(current):
    snapshot = dict(wire(current), live=True, notes=[], incident_ids=[], active_incident_id=None)
    snapshot["last_received_at"] = snapshot["timestamp"]
    return build_document(Projection(str(current["tenant_id"]), 1, str(current["id"]), 1, snapshot))


def test_search_document_carries_provider_and_rule_url(v1):
    """Requirements: alert operations 3; alerts technical 6 (REV-55)."""
    grafana = document(created(v2(), adapter=GRAFANA, raw=member(generatorURL=RULE)))
    assert grafana["provider"] == grafana["display"]["provider"] == "grafana"
    assert grafana["alert_rule_url"] == RULE and grafana["missing_alert_rule_url"] is False
    # Snapshots recorded before REV-55 hold neither key.
    older_v1 = {k: v for k, v in created(v1, "v1").items() if k not in ("provider", "alert_rule_url")}
    legacy = document(older_v1)
    assert legacy["provider"] == "api" and legacy["missing_provider"] is False
    assert legacy["alert_rule_url"] is None and legacy["missing_alert_rule_url"] is True
    older_v2 = {k: v for k, v in created(v2()).items() if k not in ("provider", "alert_rule_url")}
    assert document(older_v2)["missing_provider"] is True
