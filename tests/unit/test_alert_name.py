from datetime import UTC, datetime, timedelta
import hashlib
from uuid import uuid4

import pytest

from keep.alerts.lifecycle import apply_source
from keep.alerts.presentation import present_alert
from keep.cel import compile_expression
from keep.cel.catalog import FIELDS, RULE_FIELDS, alert_name
from keep.configuration.models import COLUMNS, GROUPABLE, SORTABLE
from keep.correlation.evidence import GroupField, group_key
from keep.correlation.runtime import _fields
from keep.ingestion.native import canonical, identity
from keep.maintenance.processing import _snapshot
from keep.search import reader
from keep.search.projection import Projection, build_document, index_mapping
from keep.serialization import wire

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
OPERATOR = uuid4()


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
        "time_created": "31-10-2026 11:59:00",
        **extra,
    }


def created(payload, version="v2"):
    key = identity(payload, version, OPERATOR)[0]
    current, _ = apply_source(
        None,
        {
            "payload": payload,
            "received_at": NOW,
            "version": version,
            "tenant_id": uuid4(),
            "id": uuid4(),
            "key_field": key,
            "operator_id": OPERATOR,
        },
    )
    return current


def test_only_a_supplied_name_is_stored_and_the_default_is_the_key(v1):
    """Requirements: alert operations 3, 5 (REV-54)."""
    named = created(v2(name="Checkout errors"))
    unnamed = created(v2())
    legacy = created(v1, "v1")
    assert named["name"] == alert_name(named) == "Checkout errors"
    assert unnamed["name"] is None and alert_name(unnamed) == unnamed["key_field"]
    assert legacy["name"] is None and alert_name(legacy) is None
    assert alert_name({"schema_version": "v2", "key_field": "k"}) == "k"
    assert present_alert(unnamed)["name"] == unnamed["key_field"]
    assert present_alert(legacy)["name"] is None
    assert "name" not in present_alert({"id": "partial"})


def test_name_is_fixed_once_the_alert_exists():
    """Requirements: alert operations 7 (REV-54)."""
    current = created(v2(name="Checkout errors"))
    item = {
        "payload": v2(name="Checkout errors", message="Still failing", status="resolved"),
        "received_at": NOW + timedelta(minutes=1),
        "version": "v2",
        "key_field": current["key_field"],
        "id": uuid4(),
    }
    updated, changed = apply_source(current, item)
    assert changed and updated["name"] == "Checkout errors"


def test_catalog_offers_name_to_feed_rules_and_presets():
    """Requirements: alert operations 3; REV-44; REV-54."""
    assert FIELDS["name"].kind == "string" and FIELDS["name"].nullable
    assert FIELDS["name"].max_bytes == 1024
    assert "name" in RULE_FIELDS
    assert {"name"} <= SORTABLE <= COLUMNS and "name" in GROUPABLE
    assert "name" in reader.GROUPABLE
    assert reader.group_filter("name", "Checkout errors", NOW) == {
        "term": {"name": "Checkout errors"}
    }
    assert reader.group_filter("name", None, NOW) == {"term": {"missing_name": True}}
    mapping = index_mapping()["properties"]
    assert mapping["name"] == {"type": "keyword", "ignore_above": 1024}
    assert mapping["missing_name"] == {"type": "boolean"}


@pytest.mark.parametrize("rule", [False, True])
def test_cel_name_reads_the_effective_name(v1, rule):
    """Requirements: alert operations 3, 4 (REV-54)."""
    named = created(v2(name="Checkout errors"))
    unnamed = created(v2())
    legacy = created(v1, "v1")
    assert compile_expression('name == "Checkout errors"', rule=rule).evaluate(named, NOW)
    key = unnamed["key_field"]
    assert compile_expression(f'name == "{key}"', rule=rule).evaluate(unnamed, NOW)
    # A proof snapshot without the name key reads the same way.
    snapshot = {k: v for k, v in unnamed.items() if k != "name"}
    assert compile_expression(f'name == "{key}"', rule=rule).evaluate(snapshot, NOW)
    # V1 has no name; string matching on null is false.
    assert not compile_expression('name.startsWith("C")', rule=rule).evaluate(legacy, NOW)
    assert not compile_expression(f'name == "{key}"', rule=rule).evaluate(legacy, NOW)


def test_maintenance_proof_of_unnamed_alerts_is_unchanged(v1):
    """Requirements: maintenance 6; alert operations 5 (REV-54)."""
    unnamed = created(v2())
    snapshot = _snapshot(unnamed)
    assert "name" not in snapshot
    # Byte-identical to the snapshot recorded before names existed.
    # Proof from then had no object either; v2 proof still omits it (REV-77).
    before = {k: unnamed[k] for k in sorted(RULE_FIELDS - {"name", "object"})}
    before["time_created"] = before["time_created"].astimezone(UTC)
    assert canonical(snapshot) == canonical(wire(before))
    assert "name" not in _snapshot(created(v1, "v1"))
    assert _snapshot(created(v2(name="Checkout errors")))["name"] == "Checkout errors"


def test_correlation_resolves_names_missing_from_older_snapshots():
    """Requirements: correlation 3; alert operations 5 (REV-54)."""
    unnamed = created(v2())
    older = {k: v for k, v in wire(unnamed).items() if k != "name"}
    assert _fields(older)["name"] == unnamed["key_field"]
    assert _fields(wire(created(v2(name="N"))))["name"] == "N"
    field = (GroupField("name", "string"),)
    assert group_key(field, older) == group_key(field, _fields(wire(unnamed)))
    assert group_key(field, older).canonical == (
        b'[["name","string","' + unnamed["key_field"].encode() + b'"]]'
    )


def document(current):
    snapshot = dict(wire(current), live=True, notes=[], incident_ids=[], active_incident_id=None)
    snapshot["last_received_at"] = snapshot["timestamp"]
    return build_document(Projection(str(current["tenant_id"]), 1, str(current["id"]), 1, snapshot))


def test_search_document_carries_the_effective_name_and_its_tokens(v1):
    """Requirements: alert operations 3; alerts technical 6 (REV-54)."""
    named = document(created(v2(name="Disk Full")))
    assert named["name"] == named["display"]["name"] == "Disk Full"
    assert named["missing_name"] is False
    assert {"disk", "full"} <= set(named["search_tokens"])
    unnamed_alert = created(v2())
    unnamed = document(unnamed_alert)
    assert unnamed["name"] == unnamed_alert["key_field"]
    assert unnamed_alert["key_field"] in unnamed["search_tokens"]
    legacy = document(created(v1, "v1"))
    assert legacy["name"] is None and legacy["missing_name"] is True


def test_unnamed_key_is_the_format_1_digest():
    """Requirements: alert operations 5 (REV-54)."""
    current = created(v2())
    material = identity(v2(), "v2", OPERATOR)[2]
    assert material.startswith(b"alerts:v2:identity:1\n")
    assert current["key_field"] == hashlib.sha256(material).hexdigest()
