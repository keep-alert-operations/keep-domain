from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import json
import math
from typing import Callable

from appchi.cel import CompiledExpression
from appchi.cel.catalog import FIELDS, storage_name
from appchi.cel.compiler import PROFILE
from appchi.alerts.presentation import present_alert
from appchi.shared.crypto import EnvelopeCipher
from appchi.shared.errors import AppError, unavailable
from .projection import SORTABLE, assert_complete, canonical
from .text import query_tokens


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

    def _close(self, pit: str):
        try:
            self.client.close_point_in_time(id=pit)
        except Exception:
            pass  # An abandoned PIT still has a bounded server lifetime.

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
    ) -> FeedPage:
        self.authorize(scope)  # every page, before decrypting/using any PIT
        if type(page_size) is not int or not 1 <= page_size <= 200:
            raise AppError("invalid_page_size", "Page size must be between 1 and 200")
        ordering, terms = (
            ordering if ordering is not None else sort_spec(sort, direction),
            query_tokens(q),
        )
        digest = sha256(
            canonical(
                {
                    "source": expression.source,
                    "profile": PROFILE,
                    "q": terms,
                    "suppressed": include_suppressed,
                    "sort": ordering,
                }
            )
        ).hexdigest()
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
            response = self.client.search(**arguments)
            assert_complete(response)
            current_pit = response.get("pit_id", current_pit)
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
            rows = []
            for hit in hits:
                document = hit["_source"]
                if (
                    document.get("tenant_id") != scope.tenant_id
                    or document.get("deleted") is not False
                ):
                    raise unavailable("search_scope_mismatch")
                if hit["_id"] in retained:
                    rows.append(present_alert(document["display"]))
            snapshot["pit"] = current_pit
            snapshot["seen"] += len(hits)
            next_cursor = None
            if hits and snapshot["seen"] < total["value"]:
                snapshot["after"] = hits[-1]["sort"]  # last examined, even when purged
                next_cursor = self._seal_cursor(snapshot, scope)
            else:
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
