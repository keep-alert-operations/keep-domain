"""Elasticsearch projection and immutable, authorized search snapshots."""

from .projection import Projection, VisibilityProof, build_document, index_mapping
from .reader import AlertGroup, FeedPage, GroupPage, SearchReader, SearchScope, SearchState

__all__ = [
    "Projection",
    "VisibilityProof",
    "build_document",
    "index_mapping",
    "AlertGroup",
    "FeedPage",
    "GroupPage",
    "SearchReader",
    "SearchScope",
    "SearchState",
]

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
