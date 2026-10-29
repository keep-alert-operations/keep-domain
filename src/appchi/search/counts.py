"""Bounded exact count batches sharing one PIT and one database query clock."""

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import time
from typing import Callable
from uuid import uuid4

from appchi.cel import CompiledExpression
from appchi.cel.compiler import PROFILE, epoch_us
from appchi.shared.errors import AppError, unavailable
from .projection import assert_complete
from .text import query_tokens


@dataclass(frozen=True)
class CountQuery:
    expression: CompiledExpression
    q: str = ""
    include_suppressed: bool = False


@dataclass(frozen=True)
class CountState:
    index_epoch: str
    committed_seq: int
    searchable_seq: int
    purge_generation: int
    verified_at: str | None
    maintenance_generation: int
    maintenance_pending: bool
    maintenance_completion: str

    def consistency(self):
        return (
            self.index_epoch,
            self.purge_generation,
            self.maintenance_generation,
            self.maintenance_pending,
            self.maintenance_completion,
        )


@dataclass(frozen=True)
class CountBatch:
    observation_id: str
    counts: dict[str, int]
    evaluated_at: str
    watermark: dict
    observed: dict
    updating: bool
    updating_suppression: bool
    next_change_at: str | None = None


class CountReader:
    """Caller supplies current authorization/configuration revalidation from PG.

    All-or-unavailable is deliberate: an incomplete subsearch never becomes zero
    or a successful count. No completed observations are cached.
    """

    def __init__(self, client, index: str):
        self.client, self.index = client, index

    def read(
        self,
        expressions: dict[str, CompiledExpression | CountQuery],
        tenant_id: str,
        *,
        evaluated_at: datetime,
        before: CountState,
        revalidate: Callable[[], CountState],
        deadline: float | None = None,
    ) -> CountBatch:
        deadline = deadline if deadline is not None else time.monotonic() + 10
        if len(expressions) > 24:
            raise AppError("invalid_count_batch", "At most 24 queries are allowed.", 422)
        if not before.verified_at or before.index_epoch == "uninitialized":
            raise unavailable("search_not_verified")
        pits: set[str] = set()

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0.05:
                raise unavailable("count_deadline")
            return value

        def client():
            return self.client.options(request_timeout=min(5.0, remaining()), max_retries=0)

        try:
            # Identical query/profile contexts, even distinct preset IDs, need
            # one ES subsearch; every output key still receives its own result.
            unique, positions = {}, {}
            for key, item in expressions.items():
                query = item if isinstance(item, CountQuery) else CountQuery(item)
                context = (
                    PROFILE,
                    query.expression.source,
                    tuple(query_tokens(query.q)),
                    query.include_suppressed,
                )
                if context not in unique:
                    unique[context] = query
                positions[key] = list(unique).index(context)
            totals = []
            changes = []
            if unique:
                opened = client().open_point_in_time(
                    index=self.index,
                    keep_alive="30s",
                    allow_partial_search_results=False,
                )
                if isinstance(opened.get("id"), str):
                    pits.add(opened["id"])
                assert_complete(opened)
                if not pits:
                    raise unavailable("search_snapshot_unavailable")
                pit = opened["id"]
                searches = []
                for query in unique.values():
                    scoped = query.expression.scoped_query(
                        tenant_id, evaluated_at, include_suppressed=query.include_suppressed
                    )
                    tokens = [{"term": {"search_tokens": term}} for term in query_tokens(query.q)]
                    scoped["bool"]["filter"].extend(tokens)
                    # The next dismissal end among matching rows, hidden ones included,
                    # so a count view can refresh when an alert returns (REV-49).
                    changing = query.expression.scoped_query(
                        tenant_id, evaluated_at, include_suppressed=True
                    )
                    changing["bool"]["filter"].extend(
                        [*tokens, {"range": {"dismissed_until": {"gt": epoch_us(evaluated_at)}}}]
                    )
                    searches.extend(
                        [
                            {"allow_partial_search_results": False},
                            {
                                "pit": {"id": pit, "keep_alive": "30s"},
                                "size": 0,
                                "track_total_hits": True,
                                "timeout": f"{max(1, int(remaining() * 1000))}ms",
                                "query": scoped,
                                "aggs": {
                                    "next_change": {
                                        "global": {},
                                        "aggs": {
                                            "scoped": {
                                                "filter": changing,
                                                "aggs": {
                                                    "at": {"min": {"field": "dismissed_until"}}
                                                },
                                            }
                                        },
                                    }
                                },
                            },
                        ]
                    )
                response = client().msearch(searches=searches)
                responses = response.get("responses", [])
                # Collect every replacement context before checking any result,
                # so a failure in the first sibling cannot leak later contexts.
                for result in responses:
                    if isinstance(result.get("pit_id"), str):
                        pits.add(result["pit_id"])
                if len(responses) != len(unique):
                    raise unavailable("count_incomplete")
                for result in responses:
                    if "error" in result or result.get("status", 200) >= 400:
                        raise unavailable("count_search_failed")
                    assert_complete(result)
                    shards = result.get("_shards", {})
                    if (
                        result.get("timed_out") is not False
                        or type(shards.get("total")) is not int
                        or shards["total"] < 0
                        or shards.get("successful") != shards["total"]
                        or shards.get("failed") != 0
                    ):
                        raise unavailable("count_incomplete")
                    total = result.get("hits", {}).get("total", {})
                    if (
                        total.get("relation") != "eq"
                        or type(total.get("value")) is not int
                        or total["value"] < 0
                    ):
                        raise unavailable("search_total_inexact")
                    totals.append(total["value"])
                    at = (
                        result.get("aggregations", {})
                        .get("next_change", {})
                        .get("scoped", {})
                        .get("at", {})
                        .get("value")
                    )
                    if at is not None:
                        changes.append(int(round(at)))
            remaining()
            observed = revalidate()
            if before.consistency() != observed.consistency():
                raise AppError(
                    "count_snapshot_changed", "Count context changed; retry from fresh state.", 409
                )
            remaining()
            return CountBatch(
                str(uuid4()),
                {key: totals[pos] for key, pos in positions.items()},
                evaluated_at.isoformat(),
                asdict(before),
                asdict(observed),
                before.searchable_seq < observed.committed_seq,
                before.maintenance_pending,
                (
                    datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=min(changes))
                ).isoformat()
                if changes
                else None,
            )
        except AppError:
            raise
        except Exception as exc:
            raise unavailable("count_search_unavailable") from exc
        finally:
            for position, pit in enumerate(sorted(pits)):
                try:
                    timeout = max(
                        0.01, min(0.25, (deadline - time.monotonic()) / (len(pits) - position))
                    )
                    self.client.options(request_timeout=timeout, max_retries=0).close_point_in_time(
                        id=pit
                    )
                except Exception:
                    pass  # Unknown cleanup outcome is bounded by the 30-second PIT lifetime.
