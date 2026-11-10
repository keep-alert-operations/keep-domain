from datetime import UTC, datetime

from pydantic import ValidationError
import pytest

from keep.cel import compile_expression
from keep.configuration.models import (
    DashboardDefinition,
    IncidentCountPanel,
    images_of,
    incident_statuses,
    presets_of,
    referenced_presets_of,
)
from keep.search.counts import MAX_INCIDENTS, CountQuery, CountReader, CountState
from keep.shared.errors import AppError

PRESET = "00000000-0000-4000-8000-000000000002"
OTHER = "00000000-0000-4000-8000-000000000003"
TENANT = "00000000-0000-4000-8000-000000000009"
NOW = datetime(2026, 11, 10, 12, tzinfo=UTC)
STATE = CountState("epoch", 5, 5, 0, NOW.isoformat(), 0, False, "none")


def panel(n, **fields):
    return {"id": f"00000000-0000-4000-8000-00000000001{n}", "x": 3 * n, "y": 0, "w": 3, "h": 2, **fields}


def test_incident_count_panels_reference_and_count_their_preset():
    """Requirements: REV-69; dashboard operations 2, 3 and 14."""
    board = DashboardDefinition(
        name="Board",
        panels=[
            panel(0, preset_id=PRESET),
            panel(1, type="incident_count", preset_id=OTHER),
            panel(2, type="table", preset_id=PRESET),
        ],
    )
    incidents = board.panels[1]
    assert isinstance(incidents, IncidentCountPanel)
    assert (incidents.incident_status, incidents.thresholds) == ("both", [])
    # Incident count panels are counted in the batch and referenced like count panels.
    assert presets_of(board.panels) == [PRESET, OTHER]
    assert referenced_presets_of(board.panels) == [PRESET, OTHER]
    assert images_of(board.panels) == []
    assert incidents.model_dump() == {
        "id": "00000000-0000-4000-8000-000000000011",
        "title": None,
        "x": 3,
        "y": 0,
        "w": 3,
        "h": 2,
        "link": None,
        "type": "incident_count",
        "preset_id": OTHER,
        "incident_status": "both",
        "thresholds": [],
    }


@pytest.mark.parametrize(
    ("status", "stored"),
    [("open", ("open",)), ("investigating", ("investigating",)), ("both", ("open", "investigating"))],
)
def test_incident_status_choices_map_to_stored_statuses(status, stored):
    """Requirements: REV-69; dashboard operations 3."""
    board = DashboardDefinition(
        name="Board",
        panels=[
            panel(
                0,
                type="incident_count",
                preset_id=PRESET,
                incident_status=status,
                thresholds=[{"lower_bound": "1", "color": "green"}, {"lower_bound": "4", "color": "red"}],
            )
        ],
    )
    assert board.panels[0].incident_status == status
    assert incident_statuses(status) == stored


@pytest.mark.parametrize(
    "fields",
    [
        {"type": "incident_count"},
        {"type": "incident_count", "preset_id": "not-a-uuid"},
        {"type": "incident_count", "preset_id": PRESET, "incident_status": "resolved"},
        {"type": "incident_count", "preset_id": PRESET, "incident_status": "firing"},
        {"type": "incident_count", "preset_id": PRESET, "incident_status": None},
        {
            "type": "incident_count",
            "preset_id": PRESET,
            "thresholds": [{"lower_bound": "4", "color": "red"}, {"lower_bound": "4", "color": "blue"}],
        },
        {"type": "incident_count", "preset_id": PRESET, "rows": 5},
    ],
)
def test_invalid_incident_count_panels_are_rejected(fields):
    """Requirements: REV-69; dashboard operations 3 and 14."""
    with pytest.raises(ValidationError):
        DashboardDefinition(name="Board", panels=[panel(0, **fields)])


class FakeSearch:
    """Answers each msearch body with a canned total and incident aggregation."""

    def __init__(self, answers):
        self.answers, self.bodies = answers, []

    def options(self, **_):
        return self

    def open_point_in_time(self, **_):
        return {"id": "pit", "_shards": {"total": 1, "successful": 1, "failed": 0}}

    def close_point_in_time(self, **_):
        return {}

    def msearch(self, searches):
        bodies = searches[1::2]
        self.bodies.extend(bodies)
        responses = []
        for body, (total, aggregation) in zip(bodies, self.answers):
            result = {
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "failed": 0},
                "hits": {"total": {"value": total, "relation": "eq"}},
                "aggregations": {"next_change": {"scoped": {"at": {"value": None}}}},
            }
            if "incidents" in body["aggs"]:
                result["aggregations"]["incidents"] = aggregation
            responses.append(result)
        return {"responses": responses}


def buckets(owners, other=0):
    return {
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": other,
        "buckets": [{"key": key, "doc_count": count} for key, count in owners.items()],
    }


def test_count_batches_report_each_incident_owner_once_with_its_alerts():
    """Requirements: REV-69; dashboard operations 6, 10 and 11."""
    expression = compile_expression('alert.severity == "critical"')
    search = FakeSearch([(6, buckets({"inc-212": 3, "inc-215": 2})), (6, None)])
    batch = CountReader(search, "index").read(
        {
            "incidents": CountQuery(expression, incidents=True),
            "alerts": CountQuery(expression),
        },
        TENANT,
        evaluated_at=NOW,
        before=STATE,
        revalidate=lambda: STATE,
    )
    assert batch.counts == {"incidents": 6, "alerts": 6}
    assert batch.incidents == {"incidents": {"inc-212": 3, "inc-215": 2}}
    # The incident query and the plain count stay separate subsearches in one PIT.
    assert len(search.bodies) == 2
    terms = search.bodies[0]["aggs"]["incidents"]["terms"]
    assert terms == {
        "field": "active_incident_id",
        "size": MAX_INCIDENTS + 1,
        "shard_size": MAX_INCIDENTS + 1,
    }
    assert "incidents" not in search.bodies[1]["aggs"]


def test_more_incidents_than_the_bound_are_reported_as_none_not_partial():
    """Requirements: REV-69; dashboard operations 11."""
    expression = compile_expression("true")
    many = {f"inc-{n}": 1 for n in range(MAX_INCIDENTS + 1)}
    for aggregation in (buckets(many), buckets({"inc-1": 1}, other=4)):
        batch = CountReader(FakeSearch([(9, aggregation)]), "index").read(
            {"p": CountQuery(expression, incidents=True)},
            TENANT,
            evaluated_at=NOW,
            before=STATE,
            revalidate=lambda: STATE,
        )
        assert batch.incidents == {"p": None}


@pytest.mark.parametrize(
    "aggregation",
    [
        None,
        {"buckets": "x"},
        {"doc_count_error_upper_bound": 2, "sum_other_doc_count": 0, "buckets": []},
        buckets({"inc-1": 0}),
    ],
)
def test_incomplete_incident_aggregations_make_the_batch_unavailable(aggregation):
    """Requirements: REV-69; dashboard operations 11."""
    search = FakeSearch([(1, aggregation)])
    if aggregation is None:
        search.answers = [(1, {})]
    with pytest.raises(AppError) as raised:
        CountReader(search, "index").read(
            {"p": CountQuery(compile_expression("true"), incidents=True)},
            TENANT,
            evaluated_at=NOW,
            before=STATE,
            revalidate=lambda: STATE,
        )
    assert raised.value.status == 503
