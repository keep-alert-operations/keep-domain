from dataclasses import replace
from uuid import uuid4

import pytest

from keep.correlation.evidence import (
    Boundary,
    CorrelationProofError,
    EvidenceState,
    ReplayTransition,
    replay_alert,
)
from test_correlation_evidence import at, BUDGET, rule, snapshot


def replay(state, current, events, now=4):
    return replay_alert(state, current, events, now=at(now), change_order=100, budgets=BUDGET)


def proof():
    current = snapshot(revision=9)
    current = replace(
        current,
        fields={**current.fields, "id": str(current.id), "tenant_id": str(current.tenant_id)},
    )
    fields = current.fields
    created = ReplayTransition(
        uuid4(), Boundary(at(0), 10), None, fields, False, True, new_logical_alert=True
    )
    qualified = ReplayTransition(
        uuid4(), Boundary(at(1), 0), fields, fields, True, False, scheduled=True
    )
    return current, created, qualified


def test_replay_current_revision_only_after_complete_original_field_proof():
    current, created, qualified = proof()
    original = EvidenceState(rule())
    state = replay(original, current, [created, qualified])
    assert len(state.memberships) == 1
    assert state.memberships[0].observed_revision == 9
    assert state.memberships[0].input_id == qualified.id
    assert state.memberships[0].start == at(1)
    changed = {**current.fields, "message": "other"}
    lost = ReplayTransition(uuid4(), Boundary(at(2), 20), current.fields, changed, False, False)
    recovered = ReplayTransition(
        uuid4(), Boundary(at(3), 30), changed, current.fields, False, False
    )
    state = replay(original, current, [created, qualified, lost, recovered])
    assert state.memberships[0].start == at(3)
    assert state.memberships[0].input_id == recovered.id
    assert (
        replay(original, replace(current, fields=changed), [created, qualified, lost]).memberships
        == ()
    )


def test_replay_withdrawal_expiry_and_resets_do_not_restore_old_qualification():
    current, created, qualified = proof()
    state = EvidenceState(rule())
    # Withdrawn qualifier omitted from authoritative replay; source arrival was suppressed.
    assert replay(state, current, [created]).memberships == ()
    assert replay(state, current, [created, qualified], now=11).memberships == ()
    reset = replace(state, rule=replace(state.rule, epoch_boundary=Boundary(at(2), 20)))
    repeat = ReplayTransition(
        uuid4(), Boundary(at(3), 30), current.fields, current.fields, False, False
    )
    assert replay(reset, current, [created, qualified, repeat]).memberships == ()


def test_replay_rejects_missing_or_contradictory_proof():
    current, created, qualified = proof()
    for events in (
        [qualified],
        [created, replace(qualified, before={})],
        [created, replace(qualified, after={})],
    ):
        with pytest.raises(CorrelationProofError):
            replay(EvidenceState(rule()), current, events)
