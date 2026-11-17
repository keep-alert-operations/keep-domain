"""Directory verification: completeness, fences and structured failure reasons.

Requirements: REV-73; identity configuration 7, 9; worker scope 4.
"""

from datetime import UTC, datetime

import pytest

from keep.identity.directory import (
    FAILURE_DEADLINE,
    FAILURE_TOO_LARGE,
    FAILURE_UNAVAILABLE,
    AcceptedDirectory,
    DirectoryEvidence,
    DirectoryObject,
    DirectoryUnavailable,
    DirectoryVerifier,
    PrincipalKey,
    failure_reason,
)


def key(value):
    return PrincipalKey("company", value)


class Reader:
    source = "company"

    def __init__(self):
        self.objects = {
            key(x): DirectoryObject(key(x), "team" if x in ("root", "a", "b") else "user", x, True)
            for x in ("root", "a", "b", "user", "other")
        }
        self.edges = {
            key("root"): [key("a"), key("b")],
            key("a"): [key("root"), key("user")],
            key("b"): [key("user"), key("other")],
        }
        self.fail = set()

    def lookup(self, principal):
        if principal in self.fail:
            raise DirectoryUnavailable("secret DN must never appear in evidence")
        return self.objects[principal]

    def members(self, principal):
        return self.edges.get(principal, [])


def test_cycles_and_alternate_paths_deduplicate_people():
    result = DirectoryVerifier(Reader()).verify([key("root")], 1)
    assert result.complete
    assert result.memberships[key("root")] == {key("user"), key("other")}
    assert len(result.objects) == 5


def test_failed_refresh_retains_old_timestamp_and_membership_indefinitely():
    reader = Reader()
    old = datetime(2000, 1, 1, tzinfo=UTC)
    accepted = AcceptedDirectory()
    first = DirectoryVerifier(reader, clock=lambda: old).verify([key("root")], 1)
    accepted.accept(first)
    reader.fail.add(key("a"))
    failed = DirectoryVerifier(reader).verify([key("root")], 2)
    accepted.accept(failed)
    assert not failed.complete
    assert failed.memberships == {}
    assert accepted.degraded
    assert accepted.checkpoints[key("root")].completed_at == old
    assert accepted.eligible_members(key("root")) == {key("user"), key("other")}
    assert "secret" not in repr(failed)


def test_only_a_group_not_found_is_a_negative_fact():
    """A person not found is never negated; a group not found is (REV-76).

    Requirements: REV-76; identity configuration 8; plan B2.
    """
    reader = Reader()
    reader.objects[key("user")] = DirectoryObject(key("user"), "user", "user", False, deleted=True)
    reader.objects[key("b")] = DirectoryObject(key("b"), "team", "b", False, deleted=True)
    evidence = DirectoryVerifier(reader).verify([key("root"), key("user")], 1)
    assert evidence.complete
    assert evidence.negative_keys == {key("b")}
    assert evidence.memberships[key("user")] == frozenset()
    assert evidence.memberships[key("root")] == frozenset()


def test_incomplete_page_cannot_establish_absence():
    reader = Reader()

    def partial(group):
        yield key("user")
        raise DirectoryUnavailable("missing page")

    reader.members = partial
    evidence = DirectoryVerifier(reader).verify([key("root")], 1)
    assert not evidence.complete
    assert evidence.edges == {}
    with pytest.raises(DirectoryUnavailable):
        _ = evidence.semantic_digest
    with pytest.raises(DirectoryUnavailable):
        AcceptedDirectory().eligible_members(key("root"))


def test_generation_time_does_not_change_semantic_digest():
    reader = Reader()
    one = DirectoryVerifier(reader).verify([key("root")], 1)
    two = DirectoryVerifier(reader).verify([key("root")], 2)
    assert one.semantic_digest == two.semantic_digest
    reader.objects[key("user")] = DirectoryObject(key("user"), "user", "renamed", True)
    assert one.semantic_digest != DirectoryVerifier(reader).verify([key("root")], 3).semantic_digest


def test_known_deleted_nested_group_preserves_other_path():
    reader = Reader()
    accepted = AcceptedDirectory()
    accepted.accept(DirectoryVerifier(reader).verify([key("root")], 1))
    reader.objects[key("a")] = DirectoryObject(key("a"), "team", "a", False, deleted=True)
    reader.fail.add(key("other"))
    accepted.accept(DirectoryVerifier(reader).verify([key("root")], 2))
    assert accepted.eligible_members(key("root")) == {key("user"), key("other")}


def test_allocation_and_deadline_are_partial_not_empty_success():
    reader = Reader()
    evidence = DirectoryVerifier(reader, max_objects=2).verify([key("root")], 1)
    assert not evidence.complete
    ticks = iter([0, 61])
    evidence = DirectoryVerifier(reader, monotonic=lambda: next(ticks)).verify([key("root")], 2)
    assert not evidence.complete
    assert evidence.memberships == {}


def test_failures_carry_structured_reasons_without_exception_text():
    reader = Reader()
    reader.fail.add(key("a"))
    evidence = DirectoryVerifier(reader).verify([key("root")], 1)
    assert evidence.failure_reason == FAILURE_UNAVAILABLE
    assert set(evidence.failures) == {FAILURE_UNAVAILABLE}
    assert "secret" not in repr(evidence.failures)
    too_large = DirectoryVerifier(Reader(), max_objects=2).verify([key("root")], 2)
    assert too_large.failure_reason == FAILURE_TOO_LARGE
    ticks = iter([0, 61])
    late = DirectoryVerifier(Reader(), monotonic=lambda: next(ticks)).verify([key("root")], 3)
    assert late.failure_reason == FAILURE_DEADLINE
    assert DirectoryVerifier(Reader()).verify([key("root")], 4).failure_reason is None


def test_a_call_timeout_is_a_deadline_not_an_outage():
    """A call past its timeout didn't fit; an inline save hands it to the background.

    Requirements: REV-73; tenant access 5 (inline save); plan A22.
    """
    assert failure_reason(DirectoryUnavailable("directory_timeout")) == FAILURE_DEADLINE
    assert failure_reason(DirectoryUnavailable("directory_deadline")) == FAILURE_DEADLINE
    for code in ("directory_status_rejected", "directory_transport_failure", "other"):
        assert failure_reason(DirectoryUnavailable(code)) == FAILURE_UNAVAILABLE


def test_deadline_inside_members_is_a_deadline_failure():
    reader = Reader()
    # start, loop check before the root, then the first member's check: past 7 s.
    ticks = iter([0, 0, 8])
    evidence = DirectoryVerifier(
        reader, deadline_seconds=7, monotonic=lambda: next(ticks, 8)
    ).verify([key("root")], 1)
    assert not evidence.complete and evidence.failure_reason == FAILURE_DEADLINE
    assert evidence.failures == (FAILURE_DEADLINE,) and evidence.edges == {}


def test_failed_evidence_publishes_no_fact():
    started = datetime.now(UTC)
    evidence = DirectoryEvidence.failed("company", 5, [key("root")], started, FAILURE_TOO_LARGE)
    assert not evidence.complete and evidence.objects == {} and evidence.negative_keys == set()
    assert (
        evidence.failures == (FAILURE_TOO_LARGE,) and evidence.failure_reason == FAILURE_TOO_LARGE
    )
    with pytest.raises(ValueError):
        DirectoryEvidence.failed("company", 5, [key("root")], started, "anything else")
