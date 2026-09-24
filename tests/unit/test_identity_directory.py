from datetime import UTC, datetime

import pytest

from appchi.identity.directory import (
    AcceptedDirectory,
    DirectoryObject,
    DirectoryUnavailable,
    DirectoryVerifier,
    PrincipalKey,
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


def test_known_disable_applies_even_partial_and_stale_complete_cannot_resurrect():
    reader = Reader()
    accepted = AcceptedDirectory()
    older = DirectoryVerifier(reader).verify([key("root")], 2)
    accepted.accept(DirectoryVerifier(reader).verify([key("root")], 1))
    reader.objects[key("user")] = DirectoryObject(key("user"), "user", "user", False)
    reader.fail.add(key("other"))
    accepted.accept(DirectoryVerifier(reader).verify([key("root")], 3))
    assert accepted.eligible_members(key("root")) == {key("other")}
    accepted.accept(older)
    assert key("user") not in accepted.eligible_members(key("root"))
    reader.objects[key("user")] = DirectoryObject(key("user"), "user", "user", True)
    reader.fail.clear()
    accepted.accept(DirectoryVerifier(reader).verify([key("root")], 4))
    assert key("user") in accepted.eligible_members(key("root"))


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
