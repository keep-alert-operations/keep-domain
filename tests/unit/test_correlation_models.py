from uuid import uuid4

import pytest

from appchi.cel.compiler import COST_MODEL
from appchi.correlation import repository
from appchi.correlation.models import Definition, display_name, name_key
from appchi.shared.capacity import UNLIMITED
from appchi.shared.errors import AppError


def definition():
    return {
        "name": "Rule",
        "severity": "high",
        "conditions": [{"id": str(uuid4()), "label": "Condition", "cel": "true"}],
    }


def test_correlation_budgets_are_optional_and_unset_means_unlimited():
    """Requirements: REV-39; system completion 23."""
    configured = {
        "cost_model": COST_MODEL,
        "enabled_rules_per_tenant": 2,
        "live_groups_per_rule": 10,
        "live_evidence_per_rule": 50,
        "live_evidence_per_tenant": 100,
        "condition_cost": 100_000,
        "rule_cost": 200_000,
        "tenant_cost": 400_000,
        "digest_bucket": 5,
    }
    assert repository.limits({"correlation": configured}) == {
        key: configured[key] for key in repository.BUDGETS
    }
    for profile in (None, {}, {"qualified": False}, {"correlation": {}}):
        assert repository.limits(profile) == dict.fromkeys(repository.BUDGETS, UNLIMITED)
    partial = repository.limits({"correlation": {"enabled_rules_per_tenant": 3}})
    assert partial["enabled_rules_per_tenant"] == 3 and partial["rule_cost"] == UNLIMITED
    for invalid in (0, -1, True, "5", 2.5, UNLIMITED + 1):
        with pytest.raises(AppError, match="capacity_profile_invalid"):
            repository.limits({"correlation": {"digest_bucket": invalid}})
    with pytest.raises(AppError, match="correlation_cost_model_mismatch"):
        repository.limits({"correlation": {"cost_model": "other"}})


def test_pinned_names_collapse_unicode_spaces_without_normalizing_group_values():
    assert display_name("  Cafe\u0301\u00a0\u2003 Team  ") == "Café Team"
    assert name_key(display_name(" STRASSE ")) == name_key(display_name("Straße"))
    parsed = Definition.model_validate(definition())
    assert parsed.window_minutes == 10 and parsed.group_by == []


@pytest.mark.parametrize("name", ["", "\nRule", "Rule\tname", "x\u200by", "x" * 201])
def test_rule_names_reject_controls_or_invalid_length(name):
    with pytest.raises(ValueError):
        display_name(name)


@pytest.mark.parametrize(
    "update",
    [
        {"group_by": ["time_created"]},
        {"group_by": ["incident_ids"]},
        {"group_by": ["application", "application"]},
        {"group_by": ["suppressed"]},
        {"window_minutes": 0},
        {"window_minutes": 1.0},
        {"window_minutes": 1441},
        {"priority": 2},
        {"enabled": False},
        {"severity": "warning"},
    ],
)
def test_strict_rule_vocabulary(update):
    with pytest.raises(ValueError):
        Definition.model_validate({**definition(), **update})


def test_duplicate_cel_allowed_but_condition_names_and_ids_are_distinct():
    first = definition()
    first["conditions"].append({"id": str(uuid4()), "label": "Other", "cel": "true"})
    assert len(Definition.model_validate(first).conditions) == 2
    first["conditions"][1]["label"] = " CONDITION "
    with pytest.raises(ValueError):
        Definition.model_validate(first)
