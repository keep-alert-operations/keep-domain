"""Complete directory traversal, independent of persistence and LDAP schema.

The caller allocates generations before starting work and publishes under the
authorization guard. Failure never turns an incomplete roster into an empty one.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Callable, Iterable, Literal, Protocol


class DirectoryUnavailable(Exception):
    """No complete, authoritative answer is available (safe to expose as 503)."""


@dataclass(frozen=True, order=True)
class PrincipalKey:
    source: str
    object_id: str

    def __post_init__(self) -> None:
        if not self.source or not self.object_id:
            raise ValueError("directory identity requires source and immutable object ID")


@dataclass(frozen=True)
class DirectoryObject:
    key: PrincipalKey
    kind: Literal["user", "team"]
    label: str
    eligible: bool
    deleted: bool = False

    def __post_init__(self) -> None:
        if self.kind not in ("user", "team") or self.deleted and self.eligible:
            raise ValueError("invalid directory object")


class DirectoryReader(Protocol):
    source: str

    def lookup(self, key: PrincipalKey) -> DirectoryObject:
        """Return verified object/tombstone; uncertainty raises DirectoryUnavailable."""

    def members(self, group: PrincipalKey) -> Iterable[PrincipalKey]:
        """All direct and primary members; incomplete paging MUST raise."""


@dataclass(frozen=True)
class DirectoryEvidence:
    source: str
    generation: int
    started_at: datetime
    completed_at: datetime
    roots: frozenset[PrincipalKey]
    objects: dict[PrincipalKey, DirectoryObject]
    edges: dict[PrincipalKey, frozenset[PrincipalKey]]
    memberships: dict[PrincipalKey, frozenset[PrincipalKey]]
    complete: bool
    failures: tuple[str, ...] = ()
    negative_keys: frozenset[PrincipalKey] = frozenset()
    target_missed: bool = False

    @property
    def semantic_digest(self) -> str:
        if not self.complete:
            raise DirectoryUnavailable("incomplete_directory_evidence")
        data = {
            "objects": [
                (k.source, k.object_id, v.kind, v.label, v.eligible, v.deleted)
                for k, v in sorted(self.objects.items())
            ],
            "edges": [
                (k.object_id, sorted(x.object_id for x in v)) for k, v in sorted(self.edges.items())
            ],
        }
        return hashlib.sha256(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()


class DirectoryVerifier:
    def __init__(
        self,
        reader: DirectoryReader,
        *,
        max_objects: int = 10000,
        deadline_seconds: float = 60,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        if max_objects < 1 or not 0 < deadline_seconds <= 60:
            raise ValueError("invalid directory verification limits")
        self.reader, self.max_objects, self.deadline = reader, max_objects, deadline_seconds
        self.monotonic, self.clock = monotonic, clock

    def verify(self, roots: Iterable[PrincipalKey], generation: int) -> DirectoryEvidence:
        roots = frozenset(roots)
        if generation < 1 or not roots or any(k.source != self.reader.source for k in roots):
            raise ValueError("invalid directory verification coverage")
        started, start_tick = self.clock(), self.monotonic()
        objects: dict[PrincipalKey, DirectoryObject] = {}
        edges: dict[PrincipalKey, frozenset[PrincipalKey]] = {}
        failures: list[str] = []
        pending = deque(sorted(roots))
        scheduled = set(roots)
        if len(scheduled) > self.max_objects:
            raise ValueError("directory coverage exceeds configured allocation")
        while pending:
            if self.monotonic() - start_tick >= self.deadline:
                failures.append("verification_deadline")
                break
            key = pending.popleft()
            try:
                obj = self.reader.lookup(key)
                if obj.key != key:
                    raise DirectoryUnavailable("identity_binding_conflict")
                objects[key] = obj
                if obj.kind == "team" and not obj.deleted:
                    members = set()
                    for member in self.reader.members(key):
                        if self.monotonic() - start_tick >= self.deadline:
                            raise DirectoryUnavailable("verification_deadline")
                        if member.source != self.reader.source:
                            raise DirectoryUnavailable("cross_source_membership")
                        members.add(member)
                        if len(members) > self.max_objects:
                            raise DirectoryUnavailable("directory_allocation_exceeded")
                    unseen = members - scheduled
                    if len(scheduled | unseen) > self.max_objects:
                        raise DirectoryUnavailable("directory_allocation_exceeded")
                    edges[key] = frozenset(members)
                    pending.extend(sorted(unseen))
                    scheduled.update(unseen)
            except DirectoryUnavailable:
                # Never include exception text: LDAP errors may contain raw DNs/profiles.
                failures.append("directory_verification_incomplete")
        ended = self.clock()
        missed = (ended - started).total_seconds() > 60
        complete = not failures
        memberships: dict[PrincipalKey, frozenset[PrincipalKey]] = {}
        if complete:
            for root in roots:
                seen: set[PrincipalKey] = set()
                queue = [root]
                eligible = set()
                while queue:
                    key = queue.pop()
                    if key in seen:
                        continue
                    seen.add(key)
                    obj = objects[key]
                    if obj.kind == "user" and obj.eligible and not obj.deleted:
                        eligible.add(key)
                    elif obj.kind == "team" and not obj.deleted:
                        queue.extend(edges.get(key, ()))
                memberships[root] = frozenset(eligible)
        negatives = frozenset(k for k, obj in objects.items() if obj.deleted or not obj.eligible)
        return DirectoryEvidence(
            self.reader.source,
            generation,
            started,
            ended,
            roots,
            objects,
            edges,
            memberships,
            complete,
            tuple(failures),
            negatives,
            missed,
        )


@dataclass
class AcceptedDirectory:
    """Reference publication policy; production persists this atomically in PG.

    Coverage is explicit. A checkpoint for a subset cannot replace other roots.
    Negative generations are retained across failures and older positive results.
    """

    checkpoints: dict[PrincipalKey, DirectoryEvidence] = field(default_factory=dict)
    negatives: dict[PrincipalKey, int] = field(default_factory=dict)
    observed_generation: dict[PrincipalKey, int] = field(default_factory=dict)
    degraded: bool = False
    latest_attempt_generation: int = 0

    def accept(self, evidence: DirectoryEvidence) -> None:
        if evidence.generation > self.latest_attempt_generation:
            self.latest_attempt_generation = evidence.generation
            self.degraded = not evidence.complete or evidence.target_missed
        for key in evidence.negative_keys:
            if evidence.generation > self.observed_generation.get(key, 0):
                self.negatives[key] = evidence.generation
                self.observed_generation[key] = evidence.generation
        if not evidence.complete:
            return
        for key, obj in evidence.objects.items():
            if evidence.generation > self.observed_generation.get(key, 0):
                self.observed_generation[key] = evidence.generation
                if obj.eligible and not obj.deleted:
                    self.negatives.pop(key, None)
        for root in evidence.roots:
            current = self.checkpoints.get(root)
            if current is None or evidence.generation > current.generation:
                self.checkpoints[root] = evidence

    def eligible_members(self, root: PrincipalKey) -> frozenset[PrincipalKey]:
        if root in self.negatives:
            return frozenset()
        evidence = self.checkpoints.get(root)
        if evidence is None:
            raise DirectoryUnavailable("directory_evidence_required")
        # Traverse retained edges so a known deleted intermediate group blocks
        # that path while independently surviving alternative paths still work.
        seen: set[PrincipalKey] = set()
        pending, eligible = [root], set()
        while pending:
            key = pending.pop()
            if key in seen or key in self.negatives:
                continue
            seen.add(key)
            obj = evidence.objects[key]
            if obj.kind == "user" and obj.eligible and not obj.deleted:
                eligible.add(key)
            elif obj.kind == "team" and not obj.deleted:
                pending.extend(evidence.edges.get(key, ()))
        return frozenset(eligible)
