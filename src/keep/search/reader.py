from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import math
from typing import Callable, NamedTuple

from keep.cel import CompiledExpression, compile_expression
from keep.cel.catalog import FIELDS, storage_name
from keep.cel.compiler import PROFILE, epoch_us
from keep.alerts.dismissal import effective_suppressed
from keep.alerts.presentation import present_alert
from keep.shared.crypto import EnvelopeCipher
from keep.shared.errors import AppError, unavailable
from .projection import SORTABLE, assert_complete, canonical
from .text import query_tokens

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# REV-44 grouping vocabulary; keep.configuration.models.GROUPABLE matches it.
GROUPABLE = (
    "severity",
    "display_status",
    "application",
    "component",
    "node_name",
    "site",
    "name",
    "assignee_id",
    "active_incident_id",
)
GROUP_ORDER = {
    "severity": ("critical", "high", "warning", "clear"),
    "display_status": ("firing", "acknowledged", "resolved"),
}
MAX_GROUPS = 1000
_STATUS: dict[str, CompiledExpression] = {}


def _status_predicates(evaluated_at: datetime) -> dict[str, dict]:
    """Visible-status filters lowered by the same compiler as the Status quick views."""
    for value in GROUP_ORDER["display_status"]:
        if value not in _STATUS:
            _STATUS[value] = compile_expression(f'display_status == "{value}"')
    return {
        value: _STATUS[value].to_elasticsearch(evaluated_at)
        for value in GROUP_ORDER["display_status"]
    }


def group_filter(field: str, key: str | None, evaluated_at: datetime) -> dict:
    """The predicate one group adds to the effective filter; None is the empty group."""
    if field not in GROUPABLE:
        raise AppError("invalid_group", "Unsupported grouping field", 422)
    if field == "display_status":
        if key not in GROUP_ORDER[field]:
            raise AppError("invalid_group", "Unsupported group value", 422)
        return _status_predicates(evaluated_at)[key]
    if key is None:
        if not FIELDS[field].nullable:
            raise AppError("invalid_group", "This field has no empty group", 422)
        return {"term": {"missing_" + field: True}}
    if not isinstance(key, str) or len(key.encode("utf-8")) > FIELDS[field].max_bytes:
        raise AppError("invalid_group", "Unsupported group value", 422)
    return {"term": {field: key}}


def _group_aggregation(field: str, evaluated_at: datetime) -> dict:
    summary = {
        "severity": {
            "filters": {
                "filters": {
                    value: {"term": {"severity": value}} for value in GROUP_ORDER["severity"]
                }
            }
        }
    }
    if field == "severity":
        summary["status"] = {"filters": {"filters": _status_predicates(evaluated_at)}}
    if field == "display_status":
        return {"filters": {"filters": _status_predicates(evaluated_at)}, "aggs": summary}
    # Composite buckets are exact on any shard layout, unlike a terms aggregation.
    return {
        "composite": {
            "size": MAX_GROUPS + 1,
            "sources": [{"value": {"terms": {"field": field, "missing_bucket": True}}}],
        },
        "aggs": summary,
    }


class _Bucket(NamedTuple):
    key: str | None
    count: int
    severity: dict[str, int]
    status: dict[str, int] | None


def _buckets(field: str, aggregation: dict) -> list[_Bucket]:
    def counts(sub):
        return None if sub is None else {k: v["doc_count"] for k, v in sub["buckets"].items()}

    if field == "display_status":
        items = [(key, value) for key, value in aggregation["buckets"].items()]
    else:
        items = [(bucket["key"]["value"], bucket) for bucket in aggregation["buckets"]]
    return [
        _Bucket(key, value["doc_count"], counts(value["severity"]), counts(value.get("status")))
        for key, value in items
        if value["doc_count"] > 0
    ]


def order_groups(field: str, buckets: list[_Bucket]) -> list[_Bucket]:
    """Fixed order for severity and status; otherwise most alerts, then value. Empty last."""
    rank = GROUP_ORDER.get(field)
    if rank:
        return sorted(buckets, key=lambda item: (item.key is None, rank.index(item.key)))
    return sorted(buckets, key=lambda item: (item.key is None, -item.count, item.key or ""))


@dataclass(frozen=True)
class SearchScope:
    tenant_id: str
    visibility: str  # session/principal visibility identity, supplied after authorization
    deployment_epoch: str


@dataclass(frozen=True)
class SearchState:
    index_epoch: str
    committed_seq: int
    searchable_seq: int
    purge_generation: int
    verified_at: str | None


@dataclass(frozen=True)
class FeedPage:
    items: list[dict]
    total: int | None
    next_cursor: str | None
    evaluated_at: str
    watermark: dict
    observed: dict
    updating: bool
    close_token: str | None = None
    next_change_at: str | None = None


@dataclass(frozen=True)
class AlertGroup:
    key: str | None
    total: int | None
    severity: dict[str, int] | None
    status: dict[str, int] | None
    items: list[dict]
    next_cursor: str | None


@dataclass(frozen=True)
class GroupPage:
    groups: list[AlertGroup]
    total: int | None
    group_count: int
    next_group_cursor: str | None
    evaluated_at: str
    watermark: dict
    observed: dict
    updating: bool
    close_token: str | None = None
    next_change_at: str | None = None


def sort_spec(name: str, direction: str) -> list[dict]:
    if name not in SORTABLE or direction not in {"asc", "desc"}:
        raise AppError("invalid_sort", "Unsupported sort field or direction")
    name = storage_name(name)
    result = []
    if FIELDS[name].nullable:
        result.append({"missing_" + name: "asc"})
    if name == "severity":
        result.extend([{"severity_clear_last": "asc"}, {"severity_rank": direction}])
    else:
        result.append({name: {"order": direction, "missing": "_last"}})
    result.append({"id": "asc"})
    return result


class SearchReader:
    def __init__(
        self,
        client,
        index: str,
        cipher: EnvelopeCipher,
        *,
        clock: Callable[[], datetime],
        state: Callable[[str], SearchState],
        authorize: Callable[[SearchScope], None],
        retained_ids: Callable[[str, list[str]], set[str]],
    ):
        self.client, self.index, self.cipher = client, index, cipher
        self.clock, self.state, self.authorize, self.retained_ids = (
            clock,
            state,
            authorize,
            retained_ids,
        )

    @staticmethod
    def _aad(scope: SearchScope) -> str:
        return "search-cursor:" + sha256(canonical(asdict(scope))).hexdigest()

    def _open_cursor(self, token: str, scope: SearchScope) -> dict:
        try:
            if len(token) > 65536:
                raise ValueError("oversize")
            value = self.cipher.open(base64.urlsafe_b64decode(token), self._aad(scope))
            return json.loads(value)
        except Exception as exc:
            raise AppError(
                "invalid_cursor", "Cursor is invalid for this session and tenant", 409
            ) from exc

    def _seal_cursor(self, value: dict, scope: SearchScope) -> str:
        return base64.urlsafe_b64encode(
            self.cipher.seal(canonical(value), self._aad(scope))
        ).decode("ascii")

    def dispose(self, token: str, scope: SearchScope):
        self.authorize(scope)
        value = self._open_cursor(token, scope)
        self._close(value["pit"])

    @staticmethod
    def _cleanup_scope(scope):
        # Preview cursors also bind query/revision. Cleanup may only close a
        # snapshot, so its independent token binds the base session and tenant.
        return SearchScope(
            scope.tenant_id, scope.visibility.split(":preview:", 1)[0], scope.deployment_epoch
        )

    def close_snapshot(self, token: str, scope: SearchScope):
        self.authorize(scope)
        value = self._open_cursor(token, self._cleanup_scope(scope))
        if value.get("purpose") != "close":
            raise AppError("invalid_cursor", "A snapshot cleanup token is required", 409)
        self._close(value["pit"])

    def _close(self, pit: str):
        try:
            self.client.close_point_in_time(id=pit)
        except Exception:
            pass  # An abandoned PIT still has a bounded server lifetime.

    @staticmethod
    def _digest(expression, terms, include_suppressed, ordering, group=None) -> str:
        value = {
            "source": expression.source,
            "profile": PROFILE,
            "q": terms,
            "suppressed": include_suppressed,
            "sort": ordering,
        }
        if group is not None:
            # Ungrouped digests stay unchanged so open cursors survive an upgrade.
            value["group"] = list(group)
        return sha256(canonical(value)).hexdigest()

    def _open_snapshot(self, token, scope, digest, before, now, purpose=None) -> dict:
        snapshot = self._open_cursor(token, scope)
        if (
            snapshot.get("purpose") != purpose
            or snapshot["digest"] != digest
            or snapshot["profile"] != PROFILE
        ):
            raise AppError("query_changed", "Restart pagination after a query change", 409)
        if snapshot["watermark"]["index_epoch"] != before.index_epoch:
            raise AppError("index_changed", "Search index changed; restart pagination", 409)
        if now >= datetime.fromisoformat(snapshot["expires"]):
            self._close(snapshot["pit"])
            raise AppError("cursor_expired", "Search snapshot expired; restart pagination", 409)
        return snapshot

    def _new_snapshot(self, scope, before, now, digest, **extra) -> dict:
        opened = self.client.open_point_in_time(
            index=self.index, keep_alive="300s", allow_partial_search_results=False
        )
        assert_complete(opened)
        snapshot = {
            "pit": opened["id"],
            "expires": (now + timedelta(minutes=5)).isoformat(),
            "evaluated_at": now.isoformat(),
            "watermark": asdict(before),
            "digest": digest,
            "profile": PROFILE,
            **extra,
        }
        if self.state(scope.tenant_id).index_epoch != before.index_epoch:
            self._close(snapshot["pit"])
            raise AppError("index_changed", "Index changed while opening snapshot", 409)
        return snapshot

    def _keep_alive(self, snapshot) -> str:
        remaining_ms = math.floor(
            (datetime.fromisoformat(snapshot["expires"]) - self.clock()).total_seconds() * 1000
        )
        if remaining_ms <= 0:
            raise AppError("cursor_expired", "Search snapshot expired; restart pagination", 409)
        return f"{remaining_ms}ms"

    def _rows(self, hits, retained, scope, query_time) -> list[dict]:
        rows = []
        for hit in hits:
            document = hit["_source"]
            if document.get("tenant_id") != scope.tenant_id or document.get("deleted") is not False:
                raise unavailable("search_scope_mismatch")
            if hit["_id"] in retained:
                row = present_alert(document["display"])
                # A dismissal counts as suppression at this snapshot's clock (REV-49).
                if "suppressed" in row:
                    row["suppressed"] = effective_suppressed(row, query_time)
                rows.append(row)
        return rows

    @staticmethod
    def _next_change_aggregation(query) -> dict:
        """Earliest dismissal end after the snapshot among rows the query matches,
        ignoring the suppression filter, so a view can refresh when an alert returns.
        A global aggregation escapes the page query within the same request."""
        return {
            "global": {},
            "aggs": {"scoped": {"filter": query, "aggs": {"at": {"min": {"field": "dismissed_until"}}}}},
        }

    @staticmethod
    def _next_change(response) -> str | None:
        value = (
            response.get("aggregations", {})
            .get("next_change", {})
            .get("scoped", {})
            .get("at", {})
            .get("value")
        )
        if value is None:
            return None
        return (EPOCH + timedelta(microseconds=int(round(value)))).isoformat()

    def _change_query(self, expression, scope, query_time, terms, extra=()):
        query = expression.scoped_query(scope.tenant_id, query_time, include_suppressed=True)
        query["bool"]["filter"].extend({"term": {"search_tokens": term}} for term in terms)
        query["bool"]["filter"].extend(extra)
        query["bool"]["filter"].append({"range": {"dismissed_until": {"gt": epoch_us(query_time)}}})
        return query

    def page(
        self,
        expression: CompiledExpression,
        scope: SearchScope,
        *,
        q: str | None = None,
        include_suppressed: bool = False,
        sort: str = "last_received_at",
        direction: str = "desc",
        page_size: int = 50,
        cursor: str | None = None,
        replace_cursor: str | None = None,
        ordering: list[dict] | None = None,
        group: tuple[str, str | None] | None = None,
    ) -> FeedPage:
        """One feed page; ``group`` (field, value or None) pages one group's rows."""
        self.authorize(scope)  # every page, before decrypting/using any PIT
        if type(page_size) is not int or not 1 <= page_size <= 200:
            raise AppError("invalid_page_size", "Page size must be between 1 and 200")
        ordering, terms = (
            ordering if ordering is not None else sort_spec(sort, direction),
            query_tokens(q),
        )
        if group is not None and (
            not isinstance(group, tuple) or len(group) != 2 or group[0] not in GROUPABLE
        ):
            raise AppError("invalid_group", "Unsupported grouping field", 422)
        digest = self._digest(expression, terms, include_suppressed, ordering, group)
        now = self.clock()
        before = self.state(scope.tenant_id)
        current_pit = None
        newly_opened = not cursor
        try:
            if cursor:
                snapshot = self._open_cursor(cursor, scope)
                if snapshot["digest"] != digest or snapshot["profile"] != PROFILE:
                    raise AppError("query_changed", "Restart pagination after a query change", 409)
                if snapshot["watermark"]["index_epoch"] != before.index_epoch:
                    raise AppError("index_changed", "Search index changed; restart pagination", 409)
                expires = datetime.fromisoformat(snapshot["expires"])
                if now >= expires:
                    self._close(snapshot["pit"])
                    raise AppError(
                        "cursor_expired", "Search snapshot expired; restart pagination", 409
                    )
            else:
                expires = now + timedelta(minutes=5)
                opened = self.client.open_point_in_time(
                    index=self.index, keep_alive="300s", allow_partial_search_results=False
                )
                assert_complete(opened)
                current_pit = opened["id"]
                after_open = self.state(scope.tenant_id)
                if after_open.index_epoch != before.index_epoch:
                    raise AppError("index_changed", "Index changed while opening snapshot", 409)
                snapshot = {
                    "pit": current_pit,
                    "expires": expires.isoformat(),
                    "evaluated_at": now.isoformat(),
                    "watermark": asdict(before),
                    "digest": digest,
                    "profile": PROFILE,
                    "after": None,
                    "seen": 0,
                }
            current_pit = snapshot["pit"]
            query_time = datetime.fromisoformat(snapshot["evaluated_at"])
            query = expression.scoped_query(
                scope.tenant_id, query_time, include_suppressed=include_suppressed
            )
            query["bool"]["filter"].extend({"term": {"search_tokens": term}} for term in terms)
            if group is not None:
                query["bool"]["filter"].append(group_filter(group[0], group[1], query_time))
            remaining_ms = math.floor((expires - self.clock()).total_seconds() * 1000)
            if remaining_ms <= 0:
                raise AppError("cursor_expired", "Search snapshot expired; restart pagination", 409)
            arguments = {
                "pit": {"id": current_pit, "keep_alive": f"{remaining_ms}ms"},
                "query": query,
                "sort": ordering,
                "size": page_size,
                "track_total_hits": True,
                "allow_partial_search_results": False,
            }
            if snapshot["after"] is not None:
                arguments["search_after"] = snapshot["after"]
            if newly_opened:
                arguments["aggs"] = {
                    "next_change": self._next_change_aggregation(
                        self._change_query(
                            expression,
                            scope,
                            query_time,
                            terms,
                            [group_filter(group[0], group[1], query_time)] if group else (),
                        )
                    )
                }
            response = self.client.search(**arguments)
            assert_complete(response)
            current_pit = response.get("pit_id", current_pit)
            if newly_opened:
                snapshot["next_change_at"] = self._next_change(response)
            hits = response["hits"]["hits"]
            total = response["hits"]["total"]
            if total.get("relation") != "eq":
                raise unavailable("search_total_inexact")
            ids = [hit["_id"] for hit in hits]
            retained = self.retained_ids(scope.tenant_id, ids) if ids else set()
            observed = self.state(scope.tenant_id)
            if observed.index_epoch != before.index_epoch:
                raise AppError("index_changed", "Search index changed; restart pagination", 409)
            # Reauthorize after external work as well; a revoked user gets no rows.
            self.authorize(scope)
            purged = (
                len(retained.intersection(ids)) != len(ids)
                or observed.purge_generation != snapshot["watermark"]["purge_generation"]
            )
            rows = self._rows(hits, retained, scope, query_time)
            snapshot["pit"] = current_pit
            snapshot["seen"] += len(hits)
            next_cursor = None
            close_token = None
            if hits and snapshot["seen"] < total["value"]:
                snapshot["after"] = hits[-1]["sort"]  # last examined, even when purged
                next_cursor = self._seal_cursor(snapshot, scope)
                close_token = self._seal_cursor(
                    {"purpose": "close", "pit": current_pit}, self._cleanup_scope(scope)
                )
            elif group is None or newly_opened:
                # Sibling groups' cursors share a grouped snapshot's PIT; it stays
                # open for them until the view closes it or it expires.
                self._close(current_pit)
            if replace_cursor and not cursor:
                self.dispose(replace_cursor, scope)
            return FeedPage(
                rows,
                None if purged else total["value"],
                next_cursor,
                snapshot["evaluated_at"],
                snapshot["watermark"],
                asdict(observed),
                purged or snapshot["watermark"]["searchable_seq"] < observed.committed_seq,
                close_token,
                snapshot.get("next_change_at"),
            )
        except AppError:
            if current_pit and newly_opened:
                self._close(current_pit)
            raise
        except Exception as exc:
            if current_pit and newly_opened:
                self._close(current_pit)
            if getattr(exc, "status_code", None) == 404 and cursor:
                raise AppError(
                    "cursor_expired", "Search snapshot expired; restart pagination", 409
                ) from exc
            raise unavailable("search_unavailable") from exc

    def groups(
        self,
        expression: CompiledExpression,
        scope: SearchScope,
        *,
        group_by: str,
        q: str | None = None,
        include_suppressed: bool = False,
        sort: str = "last_received_at",
        direction: str = "desc",
        ordering: list[dict] | None = None,
        group_limit: int = 10,
        rows_per_group: int = 5,
        group_cursor: str | None = None,
    ) -> GroupPage:
        """Exact groups of one snapshot with each shown group's first rows (REV-44).

        One aggregation counts every value; one multi-search fetches the shown
        groups' rows on the same PIT. Group row cursors continue through page()
        with ``group``; the group-list cursor reruns the aggregation on the PIT.
        """
        self.authorize(scope)
        if group_by not in GROUPABLE:
            raise AppError("invalid_group", "Unsupported grouping field", 422)
        for value, high in ((group_limit, 50), (rows_per_group, 50)):
            if type(value) is not int or not 1 <= value <= high:
                raise AppError("invalid_page_size", "Group and row limits must be 1 to 50")
        if group_limit * rows_per_group > 200:
            raise AppError("invalid_page_size", "A grouped view shows at most 200 rows")
        ordering, terms = (
            ordering if ordering is not None else sort_spec(sort, direction),
            query_tokens(q),
        )
        base = self._digest(expression, terms, include_suppressed, ordering)
        digest = sha256(canonical({"base": base, "group_by": group_by})).hexdigest()
        now = self.clock()
        before = self.state(scope.tenant_id)
        current_pit = None
        newly_opened = not group_cursor
        try:
            if group_cursor:
                snapshot = self._open_snapshot(group_cursor, scope, digest, before, now, "groups")
            else:
                snapshot = self._new_snapshot(
                    scope, before, now, digest, purpose="groups", offset=0
                )
            current_pit = snapshot["pit"]
            query_time = datetime.fromisoformat(snapshot["evaluated_at"])
            query = expression.scoped_query(
                scope.tenant_id, query_time, include_suppressed=include_suppressed
            )
            query["bool"]["filter"].extend({"term": {"search_tokens": term}} for term in terms)
            keep_alive = self._keep_alive(snapshot)
            aggregations = {"groups": _group_aggregation(group_by, query_time)}
            if newly_opened:
                aggregations["next_change"] = self._next_change_aggregation(
                    self._change_query(expression, scope, query_time, terms)
                )
            response = self.client.search(
                pit={"id": current_pit, "keep_alive": keep_alive},
                query=query,
                size=0,
                track_total_hits=True,
                allow_partial_search_results=False,
                aggs=aggregations,
            )
            assert_complete(response)
            current_pit = response.get("pit_id", current_pit)
            if newly_opened:
                snapshot["next_change_at"] = self._next_change(response)
            total = response["hits"]["total"]
            if total.get("relation") != "eq":
                raise unavailable("search_total_inexact")
            buckets = _buckets(group_by, response["aggregations"]["groups"])
            if len(buckets) > MAX_GROUPS:
                raise AppError(
                    "too_many_groups",
                    f"More than {MAX_GROUPS:,} values to group; narrow the query.",
                    422,
                )
            if sum(bucket.count for bucket in buckets) != total["value"]:
                raise unavailable("group_total_inexact")
            ordered = order_groups(group_by, buckets)
            offset = snapshot["offset"]
            shown = ordered[offset : offset + group_limit]
            found = []
            if shown:
                searches = []
                for bucket in shown:
                    scoped = deepcopy(query)
                    scoped["bool"]["filter"].append(group_filter(group_by, bucket.key, query_time))
                    searches.extend(
                        [
                            {"allow_partial_search_results": False},
                            {
                                "pit": {"id": current_pit, "keep_alive": keep_alive},
                                "query": scoped,
                                "sort": ordering,
                                "size": rows_per_group,
                                "track_total_hits": False,
                            },
                        ]
                    )
                result = self.client.msearch(searches=searches)
                responses = result.get("responses", [])
                if len(responses) != len(shown):
                    raise unavailable("group_rows_incomplete")
                for item in responses:
                    if "error" in item or item.get("status", 200) >= 400:
                        raise unavailable("group_rows_failed")
                    assert_complete(item)
                    current_pit = item.get("pit_id", current_pit)
                    found.append(item["hits"]["hits"])
            ids = [hit["_id"] for hits in found for hit in hits]
            retained = self.retained_ids(scope.tenant_id, ids) if ids else set()
            observed = self.state(scope.tenant_id)
            if observed.index_epoch != before.index_epoch:
                raise AppError("index_changed", "Search index changed; restart pagination", 409)
            self.authorize(scope)
            purged = (
                len(retained.intersection(ids)) != len(ids)
                or observed.purge_generation != snapshot["watermark"]["purge_generation"]
            )
            snapshot["pit"] = current_pit
            continuing = False
            groups = []
            for bucket, hits in zip(shown, found):
                next_cursor = None
                if hits and len(hits) < bucket.count:
                    # An ordinary feed cursor for page(group=...), on the shared PIT.
                    next_cursor = self._seal_cursor(
                        {
                            "pit": current_pit,
                            "expires": snapshot["expires"],
                            "evaluated_at": snapshot["evaluated_at"],
                            "watermark": snapshot["watermark"],
                            "digest": self._digest(
                                expression,
                                terms,
                                include_suppressed,
                                ordering,
                                (group_by, bucket.key),
                            ),
                            "profile": PROFILE,
                            "after": hits[-1]["sort"],
                            "seen": len(hits),
                        },
                        scope,
                    )
                    continuing = True
                groups.append(
                    AlertGroup(
                        bucket.key,
                        None if purged else bucket.count,
                        None if purged else bucket.severity,
                        None if purged else bucket.status,
                        self._rows(hits, retained, scope, query_time),
                        next_cursor,
                    )
                )
            next_group_cursor = None
            if offset + group_limit < len(ordered):
                next_group_cursor = self._seal_cursor(
                    {**snapshot, "offset": offset + group_limit}, scope
                )
                continuing = True
            close_token = None
            if continuing or not newly_opened:
                close_token = self._seal_cursor(
                    {"purpose": "close", "pit": current_pit}, self._cleanup_scope(scope)
                )
            else:
                self._close(current_pit)
            return GroupPage(
                groups,
                None if purged else total["value"],
                len(ordered),
                next_group_cursor,
                snapshot["evaluated_at"],
                snapshot["watermark"],
                asdict(observed),
                purged or snapshot["watermark"]["searchable_seq"] < observed.committed_seq,
                close_token,
                snapshot.get("next_change_at"),
            )
        except AppError:
            if current_pit and newly_opened:
                self._close(current_pit)
            raise
        except Exception as exc:
            if current_pit and newly_opened:
                self._close(current_pit)
            if getattr(exc, "status_code", None) == 404 and group_cursor:
                raise AppError(
                    "cursor_expired", "Search snapshot expired; restart pagination", 409
                ) from exc
            raise unavailable("search_unavailable") from exc
