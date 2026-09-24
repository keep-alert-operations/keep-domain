from datetime import datetime, timezone

import pytest

from appchi.cel import CELValidationError, compile_expression

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "source,alert,expected",
    [
        ("true", {}, True),
        ("false", {}, False),
        ("true == true", {}, True),
        ("2 < 3", {}, True),
        ('alert.status == "firing"', {"status": "firing"}, True),
        ('alert.status == "resolved"', {"status": "firing"}, False),
        ("alert.node_name == null", {}, True),
        ('alert.node_name != "x"', {}, True),
        ('alert.node_name.contains("")', {}, False),
        ('!alert.node_name.contains("x")', {}, True),
        ("has(alert.node_name)", {"node_name": ""}, True),
        ('alert.node_name.contains("")', {"node_name": ""}, True),
        ('alert.node_name.startsWith("a*?")', {"node_name": "a*?b"}, True),
        ('alert.node_name.endsWith("B")', {"node_name": "ab"}, False),
        ('alert.node_name in [null,"x"]', {}, True),
        ('alert.node_name in ["x","y"]', {}, False),
        ("alert.node_name in []", {}, False),
        (
            "alert.acknowledged && !alert.suppressed",
            {"acknowledged": True, "suppressed": False},
            True,
        ),
        ("alert.occurrence_number >= 2", {"occurrence_number": 3}, True),
        ("alert.occurrence_number >= -9223372036854775808", {"occurrence_number": 0}, True),
        ("alert.opened_at < now()", {}, False),
        ("!(alert.opened_at < now())", {}, True),
        ('alert.time_created >= now() - duration("1h30m0.5s")', {"time_created": NOW}, True),
        (
            'alert.time_created == timestamp("2026-09-22T15:00:00+03:00")',
            {"time_created": NOW},
            True,
        ),
        (
            '"ab2fe852-d096-4646-8ac2-f653aa08376c" in alert.incident_ids',
            {"incident_ids": ["ab2fe852-d096-4646-8ac2-f653aa08376c"]},
            True,
        ),
        ('alert.message == "é"', {"message": "e\u0301"}, False),
        ('alert.message.contains("😀")', {"message": "failure 😀"}, True),
    ],
)
def test_checked_native_semantics(source, alert, expected):
    compiled = compile_expression(source)
    assert compiled.evaluate(alert, NOW) is expected
    assert compiled.to_elasticsearch(NOW)


@pytest.mark.parametrize(
    "source",
    [
        'alert.labels.env == "x"',
        "alert.revision == 1",
        'v_node_name == "x"',
        'alert.message.matches(".*")',
        'alert.message + "x" == "y"',
        "alert.node_name == alert.application",
        "alert.occurrence_number > 1.5",
        "alert.occurrence_number == 1u",
        "alert.occurrence_number + 1 > 2",
        'alert.status == "suspended"',
        'alert.severity.startsWith("crit")',
        'alert.application > "x"',
        "alert.suppressed == 1",
        'alert.node_name in ["x",1]',
        "[1,2].exists(x,x>1)",
        'alert.node_name[0] == "x"',
        "true ? true : false",
        'alert.time_created == timestamp("2026-09-22")',
        'alert.time_created == timestamp("2026-09-22T00:00:00.0000001Z")',
        'alert.time_created > now() - duration("-1s")',
        'alert.time_created > now() - duration("١h")',
        'alert.time_created > now() - duration("3652501h999999999999m")',
        'alert.time_created > timestamp("2026-01-01T00:00:00Z") + duration("1s") + duration("1s")',
        '"bad-uuid" in alert.incident_ids',
        "has(alert.incident_ids)",
        "alert.occurrence_number == 9223372036854775808",
    ],
)
def test_unsupported_profile_rejected(source):
    with pytest.raises(CELValidationError):
        compile_expression(source)


@pytest.mark.parametrize(
    "source",
    [
        "alert.suppressed",
        "alert.occurrence_number == 1",
        "alert.active_incident_id == null",
        "alert.time_created < now()",
        'alert.timestamp < timestamp("2026-09-22T00:00:00Z")',
    ],
)
def test_rule_field_and_clock_restrictions(source):
    with pytest.raises(CELValidationError):
        compile_expression(source, rule=True)


def test_fixed_clock_and_null_elasticsearch():
    compiled = compile_expression('alert.opened_at >= now() - duration("1s")')
    assert compiled.to_elasticsearch(NOW) == {"range": {"opened_at": {"gte": 1790078399000000}}}
    assert compile_expression("alert.node_name == null").to_elasticsearch(NOW) == {
        "bool": {"must_not": [{"exists": {"field": "node_name"}}]}
    }
    assert compile_expression('alert.node_name != "x"').to_elasticsearch(NOW) == {
        "bool": {"must_not": [{"term": {"node_name": "x"}}]}
    }


def test_literal_wildcard_escaping_and_scope():
    compiled = compile_expression('alert.message.contains("a*?b")')
    assert compiled.to_elasticsearch(NOW) == {
        "wildcard": {"message": {"value": "*a\\*\\?b*", "case_insensitive": False}}
    }
    filters = compiled.scoped_query("tenant", NOW)["bool"]["filter"]
    assert {"term": {"tenant_id": "tenant"}} in filters
    assert {"term": {"deleted": False}} in filters
    assert {"term": {"suppressed": False}} in filters


def test_limits_and_relative_overflow():
    with pytest.raises(CELValidationError):
        compile_expression(" " * 16385)
    with pytest.raises(CELValidationError):
        compile_expression("alert.node_name in [" + ",".join('"x"' for _ in range(101)) + "]")
    with pytest.raises(CELValidationError):
        compile_expression("!(true && " * 33 + "true" + ")" * 33)
    compiled = compile_expression('alert.time_created > now() + duration("1s")')
    with pytest.raises(CELValidationError):
        compiled.to_elasticsearch(datetime.max.replace(tzinfo=timezone.utc))


def test_invalid_runtime_data_does_not_become_false():
    compiled = compile_expression("alert.occurrence_number > 0")
    with pytest.raises(CELValidationError):
        compiled.evaluate({"occurrence_number": True}, NOW)
    with pytest.raises(CELValidationError):
        compiled.evaluate({}, NOW)


def test_rule_cost_is_unqualified_estimate_and_timestamps_keep_microseconds():
    compiled = compile_expression('alert.message.contains("abc")', rule=True)
    assert compiled.rule_cost_upper_bound > 32768
    compiled = compile_expression('alert.time_created == timestamp("0001-01-01T00:00:00.000001Z")')
    assert compiled.evaluate({"time_created": "0001-01-01T00:00:00.000001Z"}, NOW)
    assert compiled.to_elasticsearch(NOW)["term"]["time_created"] == -62135596799999999
