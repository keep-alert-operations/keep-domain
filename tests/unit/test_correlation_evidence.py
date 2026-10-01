from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from appchi.correlation.evidence import (
    Boundary,
    Budgets,
    Condition,
    CorrelationProofError,
    EvidenceState,
    GroupField,
    Input,
    Rule,
    Snapshot,
    apply_all,
    apply_input,
    choose_decision,
    clear_context,
    context_for,
    edit_rule,
    group_key,
    release_alert,
)

BASE = datetime(2026, 9, 22, 10, tzinfo=UTC)
TENANT = uuid4()
BUDGET = Budgets(live_groups=1000, live_evidence=10000)


def at(minutes):
    return BASE + timedelta(minutes=minutes)


class Program:
    def __init__(self, expected="match"):
        self.expected, self.source = expected, f'alert.message == "{expected}"'

    def evaluate(self, alert, evaluated_at):
        return alert["message"] == self.expected


def rule(*, groups=(), conditions=1, created=-10, rule_id=None):
    return Rule(
        rule_id or uuid4(),
        TENANT,
        at(created),
        1,
        1,
        1,
        Boundary(at(-5), 5),
        tuple(Condition(uuid4(), f"Condition {i}", Program()) for i in range(conditions)),
        tuple(groups),
    )


def snapshot(
    alert_id=None,
    revision=1,
    message="match",
    group="A",
    status="firing",
    suppressed=False,
    owner=None,
):
    return Snapshot(
        alert_id or uuid4(),
        TENANT,
        revision,
        {"message": message, "site": group, "status": status},
        status,
        suppressed,
        owner,
    )


def event(after, before=None, *, minutes=0, order=10, change_order=None, kind="source"):
    return Input(
        uuid4(),
        change_order or order,
        before,
        after,
        Boundary(at(minutes), order),
        kind,
        before is None,
    )


def apply(state, input, *, now=0, **kwargs):
    return apply_input(state, input, now=at(now), budgets=BUDGET, **kwargs)


def test_same_alert_can_satisfy_all_conditions_and_is_attached_once():
    state, alert = EvidenceState(rule(conditions=2)), snapshot()
    state = apply(state, event(alert))
    assert len(state.memberships) == 2
    decision = choose_decision((state,), {alert.id: alert}, now=at(0))
    assert decision.attachment_ids == (alert.id,)
    assert len(decision.supports) == 2


def test_derived_unsuppression_preserves_real_revision_and_original_time():
    after = snapshot(revision=4)
    before = replace(after, suppressed=True)
    effect = Input(uuid4(), 20, before, after, Boundary(at(0), 10), "scheduled", False, True)
    updated = apply(EvidenceState(rule()), effect, now=3)
    assert updated.memberships[0].observed_revision == 4
    assert updated.memberships[0].start == at(0)
    assert updated.memberships[0].expiry == at(10)
    assert apply(EvidenceState(rule()), effect, now=10).memberships == ()
    with pytest.raises(CorrelationProofError):
        apply(EvidenceState(rule()), replace(effect, derived_qualifier=False), now=3)
    with pytest.raises(CorrelationProofError):
        apply(EvidenceState(rule()), replace(effect, kind="source"), now=3)
    with pytest.raises(CorrelationProofError):
        apply(
            EvidenceState(rule()),
            replace(effect, before=replace(before, fields={"message": "old"})),
            now=3,
        )


def test_true_repeats_preserve_original_start_and_expiry_never_restore_expired():
    state, first = EvidenceState(rule()), snapshot()
    state = apply(state, event(first))
    second = replace(first, revision=2)
    state = apply(state, event(second, first, minutes=5, order=11), now=5)
    assert state.memberships[0].start == at(0) and state.memberships[0].expiry == at(10)
    assert state.memberships[0].observed_revision == 2
    assert choose_decision((state,), {second.id: second}, now=at(10)) is None
    third = replace(second, revision=3)
    state = apply(state, event(third, second, minutes=11, order=12), now=11)
    assert state.memberships == ()


def test_logic_reset_evaluates_both_sides_without_recreating_true_membership():
    state, first = EvidenceState(rule()), snapshot()
    state = apply(state, event(first))
    state = edit_rule(state, Boundary(at(1), 11), window_minutes=20)
    second = replace(first, revision=2)
    state = apply(state, event(second, first, minutes=2, order=12), now=2)
    assert state.memberships == ()
    assert state.rule.epoch == 2


def test_per_condition_false_to_true_does_not_refresh_other_condition():
    one, two = Condition(uuid4(), "one", Program("a")), Condition(uuid4(), "two", Program("b"))
    state = EvidenceState(replace(rule(), conditions=(one, two)))
    first, second = snapshot(message="a"), None
    second = replace(first, revision=2, fields={**first.fields, "message": "b"})
    state = apply(state, event(first))
    state = apply(state, event(second, first, minutes=2, order=11), now=2)
    assert len(state.memberships) == 1
    assert state.memberships[0].condition_id == two.id and state.memberships[0].start == at(2)
    assert choose_decision((state,), {second.id: second}, now=at(2)) is None


def test_group_move_a_b_a_is_new_evidence_not_reclaimed_old_group():
    state = EvidenceState(rule(groups=(GroupField("site", "string"),)))
    a = snapshot()
    state = apply(state, event(a))
    first_input = state.memberships[0].input_id
    b = replace(a, revision=2, fields={**a.fields, "site": "B"})
    state = apply(state, event(b, a, minutes=2, order=11), now=2)
    assert state.memberships[0].start == at(2)
    again = replace(b, revision=3, fields={**b.fields, "site": "A"})
    state = apply(state, event(again, b, minutes=4, order=12), now=4)
    assert len(state.memberships) == 1
    assert state.memberships[0].start == at(4)
    assert state.memberships[0].input_id != first_input


def test_group_configuration_a_b_a_never_reuses_generation():
    state = EvidenceState(rule(groups=(GroupField("site", "string"),)))
    state = edit_rule(state, Boundary(at(1), 20), grouping=(GroupField("message", "string"),))
    state = edit_rule(state, Boundary(at(2), 21), grouping=(GroupField("site", "string"),))
    assert state.rule.grouping_generation == 3 and state.rule.epoch == 3


def test_typed_full_group_values_zero_false_and_string_identity():
    keys = [
        group_key((GroupField("test", kind),), {"test": value})
        for kind, value in (("bool", True), ("int", 1), ("string", "1"))
    ]
    assert len(set(keys)) == 3
    assert group_key((GroupField("test", "bool"),), {"test": False}) is not None
    assert group_key((GroupField("test", "int"),), {"test": 0}) is not None
    assert group_key((GroupField("test", "int"),), {"test": True}) is None
    for value in (None, "", "  ", 123):
        assert group_key((GroupField("test", "string"),), {"test": value}) is None
    assert group_key((GroupField("test", "string"),), {"test": " A "}) != group_key(
        (GroupField("test", "string"),), {"test": "A"}
    )
    long = "x" * 100000 + "z"
    assert long.encode() in group_key((GroupField("site", "string"),), {"site": long}).canonical
    assert group_key((), {}) is not None


def test_delayed_input_uses_original_order_and_expiry_not_processing_time():
    state = EvidenceState(rule())
    assert apply(state, event(snapshot(), minutes=0), now=11).memberships == ()
    state = edit_rule(state, Boundary(at(1), 20), window_minutes=20)
    assert (
        apply(state, event(snapshot(), minutes=0, order=10, change_order=100), now=2).memberships
        == ()
    )


def test_scheduled_qualifier_must_be_strictly_later_than_reset_time():
    state = edit_rule(EvidenceState(rule()), Boundary(at(1), 20), window_minutes=20)
    before = snapshot(suppressed=True)
    after = replace(before, revision=2, suppressed=False)
    equal = event(after, before, minutes=1, order=99, change_order=100, kind="scheduled")
    assert apply(state, equal, now=2).memberships == ()
    later = event(after, before, minutes=1.01, order=1, change_order=101, kind="scheduled")
    assert len(apply(state, later, now=2).memberships) == 1


def test_unlink_and_resolution_barriers_require_new_transition_and_order():
    state, alert = EvidenceState(rule()), snapshot()
    state = apply(state, event(alert))
    context = state.memberships[0].context
    state = release_alert(clear_context(state, context), alert.id)
    barrier = Boundary(at(1), 20)
    repeat = replace(alert, revision=2)
    state = apply(
        state,
        event(repeat, alert, minutes=2, order=21),
        now=2,
        release_boundaries={alert.id: barrier},
        context_boundaries={context: barrier},
    )
    assert state.memberships == ()
    false = replace(repeat, revision=3, fields={**repeat.fields, "message": "different"})
    state = apply(state, event(false, repeat, minutes=3, order=22), now=3)
    true = replace(false, revision=4, fields={**false.fields, "message": "match"})
    assert (
        len(
            apply(
                state,
                event(true, false, minutes=4, order=23),
                now=4,
                release_boundaries={alert.id: barrier},
                context_boundaries={context: barrier},
            ).memberships
        )
        == 1
    )


def test_manual_ownership_and_stale_revision_are_excluded():
    state, alert = EvidenceState(rule()), snapshot()
    state = apply(state, event(alert))
    assert (
        choose_decision((state,), {alert.id: replace(alert, active_incident_id=uuid4())}, now=at(0))
        is None
    )
    assert choose_decision((state,), {alert.id: replace(alert, revision=2)}, now=at(0)) is None
    assert choose_decision((state,), {alert.id: replace(alert, suppressed=True)}, now=at(0)) is None


def test_earlier_rule_then_uuid_bytes_then_full_group_order_win():
    alert = snapshot()
    early = apply(EvidenceState(rule(created=-20)), event(alert))
    late = apply(EvidenceState(rule(created=-10)), event(alert))
    assert (
        choose_decision((late, early), {alert.id: alert}, now=at(0)).context.rule_id
        == early.rule.id
    )
    low = apply(EvidenceState(rule(rule_id=UUID(int=1))), event(alert))
    high = apply(EvidenceState(rule(rule_id=UUID(int=2))), event(alert))
    assert choose_decision((high, low), {alert.id: alert}, now=at(0)).context.rule_id == low.rule.id
    state = EvidenceState(rule(groups=(GroupField("site", "string"),)))
    b, a = snapshot(group="B"), snapshot(group="A")
    state = apply(state, event(b, order=10))
    state = apply(state, event(a, order=11))
    assert choose_decision((state,), {b.id: b, a.id: a}, now=at(0)).attachment_ids == (a.id,)


def test_complete_eligible_attachment_set_exceeds_manual_hundred_limit():
    state = EvidenceState(rule())
    alerts = {}
    for index in range(150):
        alert = snapshot()
        alerts[alert.id] = alert
        state = apply(state, event(alert, order=index + 10))
    decision = choose_decision((state,), alerts, now=at(0))
    assert len(decision.attachment_ids) == 150


def test_active_context_additions_need_any_condition_and_skip_existing_links():
    state = EvidenceState(rule(conditions=2))
    alert = snapshot()
    context = context_for(state.rule, group_key((), alert.fields))
    incident = uuid4()
    state = apply(state, event(alert), active_contexts={context: incident})
    state = replace(state, memberships=state.memberships[:1])
    assert (
        choose_decision(
            (state,), {alert.id: alert}, now=at(0), active_contexts={context: incident}
        ).existing_incident_id
        == incident
    )
    assert (
        choose_decision(
            (state,),
            {alert.id: alert},
            now=at(0),
            active_contexts={context: incident},
            linked_alerts={incident: frozenset({alert.id})},
        )
        is None
    )


def test_runtime_error_blocks_only_rule_and_budget_failure_does_not_truncate():
    class Broken(Program):
        def evaluate(self, alert, evaluated_at):
            raise ValueError("bad evaluation")

    bad = EvidenceState(replace(rule(), conditions=(Condition(uuid4(), "broken", Broken()),)))
    bad = apply(bad, event(snapshot()))
    assert bad.rule.health == "blocked" and bad.memberships == ()
    state = EvidenceState(rule(conditions=2))
    state = apply_input(state, event(snapshot()), now=at(0), budgets=Budgets(1, 1))
    assert state.rule.health == "blocked" and state.memberships == ()


def test_missing_before_is_not_a_false_baseline_and_replay_preserves_start():
    alert, state = snapshot(), EvidenceState(rule())
    original = event(alert)
    state = apply(state, original)
    assert apply(state, original) == state
    with pytest.raises(CorrelationProofError):
        apply(state, replace(event(replace(alert, revision=2), order=11), new_logical_alert=False))


def test_native_cel_condition_is_used_without_a_second_evaluator():
    from appchi.cel import compile_expression

    compiled = compile_expression('alert.message == "match"', rule=True)
    state = EvidenceState(replace(rule(), conditions=(Condition(uuid4(), "native", compiled),)))
    assert len(apply(state, event(snapshot())).memberships) == 1


def test_all_rules_receive_input_before_arbitration_and_tenant_budget_is_deterministic():
    early = EvidenceState(rule(created=-20))
    late = EvidenceState(rule(created=-10))
    alert = snapshot()
    states = apply_all(
        (late, early), event(alert), now=at(0), budgets=BUDGET, tenant_evidence_budget=1
    )
    assert states[0].rule.id == early.rule.id and len(states[0].memberships) == 1
    assert states[1].last_change_order == 10
    assert (
        states[1].rule.health == "blocked"
        and states[1].blocked_reason == "tenant_evidence_capacity_exceeded"
    )


def test_owned_alert_cannot_move_automatically_to_another_group():
    state = EvidenceState(rule(groups=(GroupField("site", "string"),)))
    first = snapshot()
    state = apply(state, event(first))
    old_context = state.memberships[0].context
    owner = uuid4()
    next_group = replace(
        first, revision=2, fields={**first.fields, "site": "B"}, active_incident_id=owner
    )
    moved = apply(
        state,
        event(next_group, first, minutes=1, order=11),
        now=1,
        active_contexts={old_context: owner},
    )
    assert moved.memberships == ()


def test_metadata_condition_reorder_keeps_evidence_and_origin_priority():
    state, alert = EvidenceState(rule(conditions=2)), snapshot()
    state = apply(state, event(alert))
    updated = edit_rule(
        state, Boundary(at(1), 11), conditions=tuple(reversed(state.rule.conditions))
    )
    assert updated.memberships == state.memberships
    assert updated.rule.epoch == state.rule.epoch
    assert updated.rule.created_at == state.rule.created_at
    assert updated.rule.revision == state.rule.revision + 1


@pytest.mark.parametrize("transitions,expected", [
    ([("other","match",1)],1),
    ([("match","match",1)],0),
    ([("other","match",-1)],0),
    ([("other","match",1),("match","other",-1),("other","match",-0.5)],0),
    ([("other","match",1),("match","match",2)],1),
])
def test_manual_reset_release_uses_normal_source_provenance(transitions, expected):
    current = snapshot(revision=8)
    provenance = tuple((snapshot(message=before).fields,snapshot(message=after).fields,at(when),False)
        for before,after,when in transitions)
    effect = Input(uuid4(),20,replace(current,suppressed=True),current,
        Boundary(at(5),20),"scheduled",False,True,provenance)
    result = apply(EvidenceState(rule()),effect,now=6,
        release_boundaries={current.id:Boundary(at(0),10)})
    assert len(result.memberships) == expected


def test_delayed_release_preserves_a_newer_source_membership():
    current = snapshot(revision=4)
    before = replace(current,revision=3,fields={**current.fields,"message":"other"})
    state = apply(EvidenceState(rule()),event(current,before,minutes=5,order=20),now=5)
    original = state.memberships[0]
    delayed = Input(uuid4(),21,replace(current,suppressed=True),current,
        Boundary(at(1),10),"scheduled",False,True)
    result = apply(state,delayed,now=6)
    assert result.memberships == (original,)
