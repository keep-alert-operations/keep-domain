"""Opt-in grouped snapshot checks on a real two-shard Elasticsearch index (REV-44)."""

from collections import Counter
from datetime import UTC, datetime, timedelta
import os
from uuid import uuid4

from elasticsearch import Elasticsearch
import pytest

from keep.cel import compile_expression
from keep.search import Projection, SearchReader, SearchScope, SearchState, index_mapping
from keep.search import reader as reader_module
from keep.search.projection import build_document
from keep.shared.errors import AppError

pytestmark = pytest.mark.compatibility

NOW = datetime(2026, 10, 26, 14, tzinfo=UTC)
APPS = ["payments-api"] * 6 + ["checkout-web"] * 5 + ["orders-api"] * 5 + ["inventory"] * 2
SEVERITIES = ["critical", "high", "warning", "clear"]


@pytest.fixture
def two_shards():
    endpoint = os.environ.get("KEEP_TEST_ELASTICSEARCH_URL")
    if not endpoint:
        pytest.skip("Set KEEP_TEST_ELASTICSEARCH_URL to an isolated real Elasticsearch service")
    ca = os.environ.get("KEEP_TEST_ELASTICSEARCH_CA")
    api_key = os.environ.get("KEEP_TEST_ELASTICSEARCH_API_KEY")
    client = Elasticsearch(
        endpoint,
        request_timeout=10,
        **({"ca_certs": ca} if ca else {}),
        **({"api_key": api_key} if api_key else {}),
    )
    index = "keep-test-groups-" + uuid4().hex
    client.indices.create(
        index=index,
        mappings=index_mapping(),
        settings={"number_of_shards": 2, "number_of_replicas": 0},
    )
    yield client, index
    client.indices.delete(index=index)
    client.close()


def snapshot(tenant, position, application, **extra):
    when = NOW - timedelta(minutes=position)
    return {
        "id": str(uuid4()),
        "tenant_id": tenant,
        "schema_version": "v2",
        "key_field": f"key-{position}",
        "operator": str(uuid4()),
        "application": application,
        "component": "cpu",
        "node_name": None if position % 4 == 0 else f"node-{position % 3}",
        "site": "eu",
        "impact": "",
        "runbook_url": None,
        "message": f"Alert {position}",
        "severity": SEVERITIES[position % 4],
        "status": "resolved" if position % 5 == 0 else "firing",
        "assignee_id": str(uuid4()) if position % 3 == 0 else None,
        "suppressed": False,
        "acknowledged": False,
        "time_created": when.isoformat(),
        "first_received_at": when.isoformat(),
        "timestamp": when.isoformat(),
        "occurrence_number": 1,
        "incident_ids": [],
        **extra,
    }


@pytest.fixture
def grouped(two_shards, cipher):
    client, index = two_shards
    tenant, other = str(uuid4()), str(uuid4())
    alerts = [snapshot(tenant, position, app) for position, app in enumerate(APPS)]
    foreign = [snapshot(other, 100, "payments-api"), snapshot(other, 101, "elsewhere")]
    operations = []
    for seq, item in enumerate(alerts + foreign, start=1):
        document = build_document(Projection(item["tenant_id"], seq, item["id"], 1, item))
        operations.extend([{"index": {"_index": index, "_id": item["id"]}}, document])
    assert client.bulk(operations=operations, refresh="wait_for")["errors"] is False
    assert client.count(index=index)["count"] == len(alerts) + len(foreign)
    state = SearchState("test-epoch", 30, 30, 0, NOW.isoformat())
    service = SearchReader(
        client,
        index,
        cipher,
        clock=lambda: NOW,
        state=lambda _: state,
        authorize=lambda _: None,
        retained_ids=lambda _, found: set(found),
    )
    return service, SearchScope(tenant, "test-session", "test-deploy"), alerts


def display_status(alert):
    if alert["status"] == "resolved":
        return "resolved"
    return "acknowledged" if alert["assignee_id"] else "firing"


def test_exact_ordered_groups_and_continuations(grouped):
    """Requirements: REV-44; preset operations 4; technical baseline 17."""
    service, scope, alerts = grouped
    expression = compile_expression("true")
    page = service.groups(expression, scope, group_by="application", rows_per_group=2)
    expected = Counter(alert["application"] for alert in alerts)
    assert [group.key for group in page.groups] == [
        "payments-api",
        "checkout-web",
        "orders-api",
        "inventory",
    ]
    assert {group.key: group.total for group in page.groups} == expected
    assert page.total == len(alerts) == sum(group.total for group in page.groups)
    assert page.group_count == 4 and page.next_group_cursor is None
    assert page.close_token is not None
    for group in page.groups:
        members = [alert for alert in alerts if alert["application"] == group.key]
        newest = sorted(members, key=lambda alert: alert["timestamp"], reverse=True)
        assert [row["id"] for row in group.items] == [alert["id"] for alert in newest[:2]]
        assert group.severity == {
            value: sum(alert["severity"] == value for alert in members) for value in SEVERITIES
        }
        assert group.status is None
        seen, cursor = [row["id"] for row in group.items], group.next_cursor
        while cursor:
            more = service.page(
                expression, scope, page_size=2, cursor=cursor, group=("application", group.key)
            )
            seen.extend(row["id"] for row in more.items)
            assert more.total == group.total
            cursor = more.next_cursor
        assert seen == [alert["id"] for alert in newest]
    # A group's cursor is bound to that group.
    with pytest.raises(AppError) as error:
        service.page(
            expression,
            scope,
            page_size=2,
            cursor=page.groups[0].next_cursor,
            group=("application", "checkout-web"),
        )
    assert error.value.code == "query_changed"


def test_empty_value_group_last_and_group_list_continuation(grouped):
    """Requirements: REV-44; preset operations 4; technical baseline 17."""
    service, scope, alerts = grouped
    expression = compile_expression("true")
    first = service.groups(expression, scope, group_by="node_name", group_limit=2)
    expected = Counter(alert["node_name"] for alert in alerts)
    ordered = sorted(expected, key=lambda key: (key is None, -expected[key], key or ""))
    assert [group.key for group in first.groups] == ordered[:2]
    assert first.group_count == len(expected) and first.next_group_cursor
    rest = service.groups(
        expression, scope, group_by="node_name", group_limit=2, group_cursor=first.next_group_cursor
    )
    assert [group.key for group in rest.groups] == ordered[2:4]
    assert ordered[-1] is None
    empty = next(group for group in first.groups + rest.groups if group.key is None)
    assert empty.total == expected[None]
    assert all(row["node_name"] is None for row in empty.items)
    with pytest.raises(AppError) as error:
        service.groups(
            expression, scope, group_by="site", group_limit=2, group_cursor=first.next_group_cursor
        )
    assert error.value.code == "query_changed"


def test_status_and_severity_groups_match_their_quick_views(grouped):
    """Requirements: REV-44; preset operations 4; technical baseline 6 and 17."""
    service, scope, alerts = grouped
    expression = compile_expression("true")
    status = service.groups(expression, scope, group_by="display_status")
    order = [
        key
        for key in ("firing", "acknowledged", "resolved")
        if any(display_status(alert) == key for alert in alerts)
    ]
    assert [group.key for group in status.groups] == order
    for group in status.groups:
        quick = service.page(compile_expression(f'display_status == "{group.key}"'), scope)
        assert group.total == quick.total
        assert all(row["display_status"] == group.key for row in group.items)
    severity = service.groups(expression, scope, group_by="severity")
    assert [group.key for group in severity.groups] == SEVERITIES
    for group in severity.groups:
        members = [alert for alert in alerts if alert["severity"] == group.key]
        assert group.status == {
            value: sum(display_status(alert) == value for alert in members)
            for value in ("firing", "acknowledged", "resolved")
        }


def test_filters_bounds_and_too_many_groups(grouped, monkeypatch):
    """Requirements: REV-44; preset operations 4 and 16."""
    service, scope, alerts = grouped
    filtered = service.groups(
        compile_expression('application == "payments-api"'), scope, group_by="severity"
    )
    assert filtered.total == 6 and sum(group.total for group in filtered.groups) == 6
    with pytest.raises(AppError) as error:
        service.groups(compile_expression("true"), scope, group_by="message")
    assert error.value.code == "invalid_group"
    with pytest.raises(AppError) as error:
        service.groups(
            compile_expression("true"), scope, group_by="site", group_limit=50, rows_per_group=5
        )
    assert error.value.code == "invalid_page_size"
    monkeypatch.setattr(reader_module, "MAX_GROUPS", 3)
    with pytest.raises(AppError) as error:
        service.groups(compile_expression("true"), scope, group_by="application")
    assert error.value.code == "too_many_groups" and error.value.status == 422
