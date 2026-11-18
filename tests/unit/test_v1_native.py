"""v1 alerts stored, evaluated, shown and searched as sent (REV-77)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from keep.alerts.lifecycle import apply_source
from keep.alerts.presentation import present_alert
from keep.alerts.v1_native import as_legacy, as_sent, legacy, sent
from keep.cel import CELValidationError, compile_expression
from keep.cel.catalog import CORRELATION_FIELDS, FIELDS, RULE_FIELDS, alert_provider
from keep.configuration.models import COLUMNS, GROUPABLE, SORTABLE
from keep.correlation.runtime import _fields
from keep.ingestion.native import canonical, identity
from keep.maintenance.processing import _snapshot
from keep.maintenance.temporal import AlertTransition, Boundary, Segment, reduce_alert
from keep.observability.sli import CLASSES, classify
from keep.search import reader
from keep.search.projection import SORTABLE as SEARCH_SORTABLE
from keep.search.projection import Projection, build_document, index_mapping
from keep.serialization import wire
from keep.shared.errors import AppError

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
OPERATOR = uuid4()


def item(payload, version="v1", at=NOW):
    key = identity(payload, version, OPERATOR)[0]
    return {
        "payload": payload,
        "received_at": at,
        "version": version,
        "tenant_id": uuid4(),
        "id": uuid4(),
        "key_field": key,
        "operator_id": OPERATOR,
    }


def v2(**extra):
    return {
        "application": "pay",
        "component": "api",
        "message": "Checkout failing",
        "severity": "critical",
        "site": "dc1",
        "impact": "Orders fail",
        "runbook_url": "https://example.org/runbook",
        "status": "firing",
        "time_created": "18-11-2026 11:59:00",
        **extra,
    }


def old_row(v1):
    """A v1 row as stored before REV-77: object in component, major as high."""
    current, _ = apply_source(None, item(dict(v1, severity="major")))
    stored = dict(current, component=current["object"], severity="high")
    del stored["object"]
    return stored


def test_v1_is_stored_as_sent(v1):
    """Requirements: REV-77; alert operations 3 and 4 (A1)."""
    current, _ = apply_source(None, item(dict(v1, severity="major")))
    assert current["object"] == "cpu" and current["component"] is None
    assert current["severity"] == "major" and current["schema_version"] == "v1"
    assert current["status"] == "firing" and current["provider"] == "api"
    error, _ = apply_source(None, item(v1))
    assert error["severity"] == "error"


def test_v1_clear_resolves_and_keeps_the_last_severity(v1):
    """Requirements: REV-77; alert operations 4 and 6 (A2)."""
    current, _ = apply_source(None, item(dict(v1, severity="major")))
    later = dict(item(dict(v1, severity="clear"), at=NOW + timedelta(minutes=1)))
    resolved, changed = apply_source(current, later)
    assert changed and resolved["status"] == "resolved" and resolved["severity"] == "major"
    first_clear, _ = apply_source(None, item(dict(v1, severity="clear")))
    assert first_clear["severity"] == "clear" and first_clear["status"] == "resolved"
    refired, _ = apply_source(first_clear, item(dict(v1, severity="warning"), at=NOW))
    assert refired["severity"] == "warning"


def test_v1_differing_severity_is_an_identity_conflict(v1):
    """Requirements: REV-77; alert operations 6 (fixed v1 severity, A2)."""
    current, _ = apply_source(None, item(dict(v1, severity="major")))
    with pytest.raises(AppError) as error:
        apply_source(current, item(dict(v1, severity="error")))
    assert error.value.code == "identity_conflict"


def test_v2_mapping_is_unchanged():
    """Requirements: REV-77; alert operations 3 (A3: v2 unchanged)."""
    current, _ = apply_source(None, item(v2(), "v2"))
    assert current["component"] == "api" and current["object"] is None
    assert current["severity"] == "critical"


def test_old_vocabulary_row_converts_on_touch_without_a_conflict(v1):
    """Requirements: REV-77; alert operations 6 (A2: convert on touch)."""
    stored = old_row(v1)
    assert legacy(stored) and not sent(stored)
    converted = as_sent(stored)
    assert converted["object"] == "cpu" and converted["component"] is None
    assert converted["severity"] == "major" and converted["revision"] == stored["revision"]
    assert as_sent(converted) is converted
    # The source update applied to the converted row sees only the real change.
    updated, changed = apply_source(converted, item(dict(v1, severity="major", message="firing")))
    assert updated["severity"] == "major" and not changed
    with pytest.raises(AppError):
        apply_source(stored, item(dict(v1, severity="major")))
    restored = as_legacy(converted)
    assert restored["component"] == "cpu" and restored["object"] is None
    assert restored["severity"] == "high"
    v2_row, _ = apply_source(None, item(v2(), "v2"))
    assert as_sent(v2_row) is v2_row and as_legacy(v2_row) is v2_row


def test_catalog_compiler_accept_v1_words():
    """Requirements: REV-77; alert operations 3 (managed catalog)."""
    assert FIELDS["object"].kind == "string" and FIELDS["object"].nullable
    assert FIELDS["component"].nullable
    assert FIELDS["severity"].values == ("critical", "high", "error", "major", "warning", "clear")
    assert "object" in RULE_FIELDS and "object" in CORRELATION_FIELDS
    for rule in (False, True):
        program = compile_expression('object == "cpu" && severity == "error"', rule=rule)
        assert program.evaluate({"object": "cpu", "severity": "error"}, NOW)
        assert not program.evaluate({"component": "cpu", "severity": "critical"}, NOW)
        assert compile_expression('severity in ["major", "high"]', rule=rule).evaluate(
            {"severity": "high"}, NOW
        )
    with pytest.raises(CELValidationError):
        compile_expression('severity == "fatal"')


def test_columns_sort_and_groups_offer_object():
    """Requirements: REV-77; REV-44 (preset columns, sort and group-by)."""
    assert {"object", "component"} <= SORTABLE <= COLUMNS
    assert "object" in GROUPABLE and "object" in reader.GROUPABLE
    assert "object" in SEARCH_SORTABLE
    assert reader.group_filter("object", "cpu", NOW) == {"term": {"object": "cpu"}}
    assert reader.group_filter("object", None, NOW) == {"term": {"missing_object": True}}
    assert reader.sort_spec("object", "asc")[0] == {"missing_object": "asc"}
    mapping = index_mapping()["properties"]
    assert mapping["object"] == {"type": "keyword", "ignore_above": 1024}
    assert mapping["missing_object"] == {"type": "boolean"}


def test_provider_reads_stored_value_for_v1():
    """Requirements: REV-77; REV-55 (Grafana can send v1)."""
    assert alert_provider({"schema_version": "v1", "provider": "grafana"}) == "grafana"
    assert alert_provider({"schema_version": "v1"}) == "api"


def document(current):
    snapshot = dict(wire(current), live=True, notes=[], incident_ids=[], active_incident_id=None)
    snapshot["last_received_at"] = snapshot["timestamp"]
    return build_document(Projection(str(current["tenant_id"]), 1, str(current["id"]), 1, snapshot))


def test_search_document_ranks_and_resolves_old_vocabulary(v1):
    """Requirements: REV-77; alerts technical 6 (projection and severity order)."""
    error, _ = apply_source(None, item(v1))
    major, _ = apply_source(None, item(dict(v1, severity="major")))
    critical, _ = apply_source(None, item(v2(), "v2"))
    high, _ = apply_source(None, item(v2(severity="high"), "v2"))
    assert document(error)["severity_rank"] == document(critical)["severity_rank"] == 0
    assert document(major)["severity_rank"] == document(high)["severity_rank"] == 1
    old = document(old_row(v1))
    assert old["object"] == "cpu" and old["component"] is None
    assert old["missing_component"] is True and old["severity"] == "major"
    assert old["display"]["object"] == "cpu"
    assert document(critical)["missing_object"] is True


def test_detail_resolves_old_vocabulary(v1):
    """Requirements: REV-77; alert operations 3 (display of unconverted rows)."""
    shown = present_alert(wire(old_row(v1)))
    assert shown["object"] == "cpu" and shown["component"] is None
    assert shown["severity"] == "major"
    v2_row, _ = apply_source(None, item(v2(), "v2"))
    shown = present_alert(wire(v2_row))
    assert shown["component"] == "api" and shown["object"] is None


def test_severity_groups_in_urgency_order():
    """Requirements: REV-77; REV-44 (severity grouping)."""
    assert reader.GROUP_ORDER["severity"] == (
        "critical", "error", "high", "major", "warning", "clear",
    )
    aggregation = reader._group_aggregation("application", NOW)
    assert set(aggregation["aggs"]["severity"]["filters"]["filters"]) == {
        "critical", "error", "high", "major", "warning", "clear",
    }
    buckets = [reader._Bucket(key, 1, {}, None) for key in ("warning", "major", "error", "high")]
    assert [b.key for b in reader.order_groups("severity", buckets)] == [
        "error", "high", "major", "warning",
    ]


def test_proof_omits_absent_object_and_tolerates_older_snapshots(v1):
    """Requirements: REV-77; maintenance 6; correlation 3 (A9)."""
    v2_row, _ = apply_source(None, item(v2(), "v2"))
    snapshot = _snapshot(v2_row)
    assert "object" not in snapshot
    expected = {k: v2_row[k] for k in sorted(RULE_FIELDS - {"name", "object"})}
    expected["time_created"] = expected["time_created"].astimezone(UTC)
    assert canonical(snapshot) == canonical(wire(expected))
    # A row read before REV-77 (no object key at all) gives the same proof.
    older = {k: v for k, v in v2_row.items() if k != "object"}
    assert canonical(_snapshot(older)) == canonical(snapshot)
    v1_row, _ = apply_source(None, item(v1))
    assert _snapshot(v1_row)["object"] == "cpu"
    # Correlation reads journal rows and proof without an object key.
    journal = {k: v for k, v in wire(old_row(v1)).items() if k != "object"}
    assert _fields(journal)["object"] is None and _fields(journal)["component"] == "cpu"
    assert _fields(wire(v1_row))["object"] == "cpu"


def test_maintenance_reducer_accepts_pre_rev77_proof_and_conversion(v1):
    """Requirements: REV-77; maintenance 6 (A9: proof chain across conversion)."""
    stored = old_row(v1)
    before_proof = {k: v for k, v in _snapshot(stored).items()}
    assert "object" not in before_proof
    converted = dict(as_sent(stored), suppressed=False)
    after_proof = _snapshot(converted)
    window = compile_expression('severity == "major"', rule=True)
    old_window = compile_expression('severity == "high"', rule=True)
    start = NOW - timedelta(hours=1)

    def segment(program, at):
        return Segment(
            uuid4(), uuid4(), 1, Boundary(at, 1, str(uuid4())), start, NOW + timedelta(hours=1),
            program,
        )

    created = AlertTransition(
        Boundary(start + timedelta(minutes=1), 2, "created"), None, before_proof, True, False
    )
    conversion = AlertTransition(
        Boundary(start + timedelta(minutes=2), 3, "converted"),
        before_proof,
        after_proof,
        kind="v1-native-conversion",
    )
    # A window rewritten to the v1 words opens its cause on the conversion.
    reduced = reduce_alert(
        uuid4(),
        (segment(window, start - timedelta(minutes=1)),),
        (created, conversion),
        now=NOW,
        recorded_at=NOW,
        proof_complete=True,
    )
    assert reduced.current_causes and reduced.final_snapshot == after_proof
    assert [c.opened.id for c in reduced.causes] == ["converted"]
    # A window in the old words matched the raw row and releases on conversion.
    old = reduce_alert(
        uuid4(),
        (segment(old_window, start - timedelta(minutes=1)),),
        (created, conversion),
        now=NOW,
        recorded_at=NOW,
        proof_complete=True,
    )
    assert not old.current_causes


def test_grafana_v1_route_has_its_own_class():
    """Requirements: REV-77; REV-74 observability 8."""
    assert "ingest_v1_grafana" in CLASSES
    assert classify("POST", "/api/ingest/v1/grafana") == "ingest_v1_grafana"
    assert classify("POST", "/api/ingest/v1/alerts") == "ingest_v1"


def test_started_window_in_old_words_holds_the_old_vocabulary(v1):
    """Requirements: REV-77; maintenance 6 (a locked window keeps its alerts suppressed)."""
    from types import SimpleNamespace

    from keep.alerts.v1_native import held_by, source_prior

    stored = dict(old_row(v1), object=None)
    start = NOW - timedelta(hours=1)

    def catalog(source):
        segment = Segment(
            uuid4(), uuid4(), 1, Boundary(start, 1, str(uuid4())), start,
            NOW + timedelta(hours=1), compile_expression(source, rule=True),
        )
        return SimpleNamespace(segments=(segment,)), str(segment.window_id)

    old, window = catalog('severity == "high"')
    assert held_by(old, stored, as_sent(stored), NOW, 5) == [window]
    prior, hold = source_prior(stored, old, NOW, 5)
    assert hold and prior["severity"] == "major"
    # Applied in the new words, stored back in the old ones, the window still matches.
    updated, _ = apply_source(prior, item(dict(v1, severity="major")))
    assert as_legacy(updated)["severity"] == "high"
    unrelated, _ = catalog('application == "other"')
    assert source_prior(stored, unrelated, NOW, 5)[1] is False
    assert source_prior(stored, None, NOW, 5)[1] is False
    # A window that has ended no longer covers the update.
    assert held_by(old, stored, as_sent(stored), NOW + timedelta(hours=2), 5) == []


def test_only_a_window_in_the_leaving_words_holds_an_alert(v1):
    """Requirements: REV-77; maintenance 6 (a window in the new words sees the converted alert)."""
    from types import SimpleNamespace

    from keep.alerts.v1_native import held_by, source_prior

    stored = dict(old_row(v1), object=None)
    start = NOW - timedelta(hours=1)

    def catalog(source):
        segment = Segment(
            uuid4(), uuid4(), 1, Boundary(start, 1, str(uuid4())), start,
            NOW + timedelta(hours=1), compile_expression(source, rule=True),
        )
        return SimpleNamespace(segments=(segment,)), str(segment.window_id)

    # Written in the new words, the window must see the converted row, so its
    # cause can open on the conversion; holding would leave the alert unsuppressed.
    new_words, window = catalog('severity == "major"')
    assert held_by(new_words, stored, as_sent(stored), NOW, 5) == []
    assert source_prior(stored, new_words, NOW, 5)[1] is False
    # Windows are evaluated on the rule snapshot, as maintenance does: a window
    # on a UUID field matches the same way before and after, so nothing is held.
    on_id, _ = catalog(f'id == "{stored["id"]}"')
    assert held_by(on_id, stored, as_sent(stored), NOW, 5) == []
    # With --reverse the leaving words are the new ones.
    converted = as_sent(stored)
    assert held_by(new_words, converted, as_legacy(converted), NOW, 5, reverse=True) == [window]
