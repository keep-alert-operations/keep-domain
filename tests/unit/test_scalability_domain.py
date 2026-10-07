"""Scalability regressions without native CEL or external infrastructure."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import random
from types import SimpleNamespace
from uuid import uuid4

from appchi.maintenance.incremental import advance, checkpoint
from appchi.maintenance.temporal import AlertTransition, Boundary, Segment, reduce_alert
from appchi.serialization import wire


BASE = datetime(2026, 10, 6, tzinfo=UTC)


class Program:
    def evaluate(self, alert, evaluated_at):
        return alert["message"] == "match"


def event(order, before, after, *, source=False, kind="source"):
    return AlertTransition(
        Boundary(BASE + timedelta(seconds=order), order, str(uuid4())),
        before,
        after,
        before is None,
        source if kind == "source" else None,
        kind,
    )


def full(alert, segments, events):
    return reduce_alert(
        alert,
        segments,
        events,
        now=events[-1].boundary.at,
        recorded_at=events[-1].boundary.at,
        proof_complete=True,
        max_work=100,
        per_input_budget=True,
        source_release_since=BASE,
    )


def seed(result, item):
    return checkpoint(
        result,
        {"original_order": item.boundary.order, "effective_at": item.boundary.at},
        generation=1,
        source_release_since=BASE,
    )


def intervals(result):
    return wire([{"start": value.start, "end": value.end} for value in result.effective_intervals])


def step(alert, state, union, item, segments=()):
    return advance(
        alert,
        state,
        union,
        item,
        segments,
        now=item.boundary.at,
        generation=1,
        source_release_since=BASE,
        max_work=100,
    )


def test_ten_thousand_repeats_keep_constant_continuation():
    alert = uuid4()
    snapshot = {"message": "match", "status": "firing", "schema_version": "v2"}
    first = event(1, None, snapshot)
    state = seed(full(alert, (), (first,)), first)
    maximum = 0
    for order in range(2, 10002):
        result, state = step(alert, state, [], event(order, snapshot, snapshot))
        assert result.causes == ()
        assert result.effective_intervals == ()
        maximum = max(maximum, len(json.dumps(state)))
    assert maximum < 512
    assert int(state["last_order"]) == 10001


def test_incremental_matches_exact_reducer_across_sources_and_manual_edits():
    rng = random.Random(813)
    alert = uuid4()
    segments = (
        Segment(
            uuid4(),
            uuid4(),
            1,
            Boundary(BASE, 0, "activation"),
            BASE,
            BASE + timedelta(seconds=55),
            Program(),
        ),
    )
    snapshot = {"message": "match", "status": "firing", "schema_version": "v2"}
    events = [event(1, None, snapshot)]
    expected = full(alert, segments, events)
    state, union = seed(expected, events[0]), intervals(expected)
    causes = {cause.id: cause for cause in expected.causes}
    qualifiers = dict((at, proof) for at, *proof in expected.qualifier_inputs)
    for order in range(2, 140):
        after = {
            **snapshot,
            "message": rng.choice(("match", "other")),
            "status": rng.choice(("firing", "resolved")),
        }
        source = after["status"] == "firing" and rng.choice((True, False))
        item = event(
            order, snapshot, after, source=source, kind=rng.choice(("source", "source", "manual"))
        )
        events.append(item)
        result, state = step(alert, state, union, item, segments)
        union = intervals(result)
        causes.update({cause.id: cause for cause in result.causes})
        qualifiers.update((at, proof) for at, *proof in result.qualifier_inputs)
        expected = full(alert, segments, events)
        assert result.current_causes == expected.current_causes
        assert union == intervals(expected)[-1:]
        assert qualifiers == dict((at, proof) for at, *proof in expected.qualifier_inputs)
        assert {(c.id, c.opened, c.closed) for c in causes.values()} == {
            (c.id, c.opened, c.closed) for c in expected.causes
        }
        snapshot = after


def test_delayed_equal_time_and_catalog_change_require_exact_replay():
    alert = uuid4()
    snapshot = {"message": "match", "status": "firing", "schema_version": "v2"}
    first = event(10, None, snapshot)
    state = seed(full(alert, (), (first,)), first)
    for second in (event(9, snapshot, snapshot), event(10, snapshot, snapshot)):
        assert (
            step(alert, state, [], replace(second, boundary=replace(second.boundary, order=11)))
            is None
        )
    changed = {**state, "generation": "2"}
    assert step(alert, changed, [], event(11, snapshot, snapshot)) is None


def test_exact_replay_work_budget_is_per_input_not_lifetime():
    alert = uuid4()
    snapshot = {"message": "match", "status": "firing", "schema_version": "v2"}
    events = [event(1, None, snapshot)]
    events.extend(event(order, snapshot, snapshot) for order in range(2, 1002))
    result = reduce_alert(
        alert,
        (),
        events,
        now=events[-1].boundary.at,
        recorded_at=events[-1].boundary.at,
        proof_complete=True,
        max_work=1,
        per_input_budget=True,
        source_release_since=BASE,
    )
    assert result.final_snapshot == snapshot


def test_evidence_persistence_does_not_rewrite_unchanged_memberships():
    from appchi.correlation.evidence import Context, GroupKey, Membership
    from appchi.correlation.runtime import EvidenceSnapshot, _persist

    tenant, rule, context_id, condition, alert, qualifier = [uuid4() for _ in range(6)]
    context = Context(tenant, rule, 1, GroupKey(b"[]"))
    member = Membership(
        context, 1, condition, alert, BASE, BASE + timedelta(minutes=1), 3, qualifier
    )
    old = {
        "rule_id": rule,
        "epoch": 1,
        "context_id": context_id,
        "condition_id": condition,
        "alert_id": alert,
        "qualifier_ref": qualifier,
        "start_at": member.start,
        "expires_at": member.expiry,
        "observed_revision": 3,
    }
    statements = []
    conn = SimpleNamespace(execute=lambda query, params: statements.append((query, params)))
    prepared = SimpleNamespace(
        tenant=tenant,
        rows=({"id": rule, "health": "healthy", "blocked_reason": None},),
        capacity={"digest_bucket": 1},
    )
    state = SimpleNamespace(
        rule=SimpleNamespace(id=rule, epoch=1, health="healthy"),
        memberships=(member,),
        blocked_reason=None,
    )
    _persist(conn, prepared, (state,), EvidenceSnapshot((old,), {context: context_id}, BASE))
    assert len(statements) == 1  # Expired/obsolete rows only; this support is untouched.
    assert "expires_at<=" in statements[0][0]
    statements.clear()
    state.memberships = (replace(member, observed_revision=4),)
    _persist(conn, prepared, (state,), EvidenceSnapshot((old,), {context: context_id}, BASE))
    assert len(statements) == 2
    assert "ON CONFLICT" in statements[1][0]
    assert statements[1][1][1].obj[0]["observed_revision"] == "4"


def test_prepared_source_relabels_only_new_cause_and_qualifier_provenance():
    from appchi.maintenance.preparation import PreparedReplay, bind_source
    from uuid import UUID, uuid5

    alert = uuid4()
    snapshot = {"message": "match", "status": "firing", "schema_version": "v2"}
    first = event(1, None, snapshot)
    new = event(2, snapshot, snapshot, source=True)
    result = full(alert, (), (first, new))
    state = seed(result, new)
    # The binding operation must also relabel a direct release's provenance.
    result = replace(
        result, qualifier_inputs=((new.boundary.at, new.boundary.id, True, new.boundary.id),)
    )
    proof = PreparedReplay(
        2,
        UUID(new.boundary.id),
        b"d" * 32,
        result,
        state,
        b"p" * 32,
        {},
        (),
        intervals(result),
        True,
    )
    actual = uuid5(alert, "actual source after another alert advanced tenant order")
    bound = bind_source(
        proof,
        {
            "id": actual,
            "kind": "source",
            "request_digest": b"d" * 32,
            "effective_at": new.boundary.at,
            "original_order": 5000,
        },
        alert,
    )
    cause = bound.result.causes[0]
    assert cause.id == uuid5(alert, "source:v2:" + str(actual))
    assert cause.opened.id == str(actual) and cause.opened.order == 5000
    assert bound.result.qualifier_inputs[0][1:] == (str(actual), True, str(actual))
    assert int(bound.continuation["last_order"]) == 5000
    assert bound.continuation["causes"][0]["id"] == str(cause.id)
