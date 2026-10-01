"""Elasticsearch projection and immutable, authorized search snapshots."""

from .projection import Projection, VisibilityProof, build_document, index_mapping
from .reader import FeedPage, SearchReader, SearchScope, SearchState

__all__ = [
    "Projection",
    "VisibilityProof",
    "build_document",
    "index_mapping",
    "FeedPage",
    "SearchReader",
    "SearchScope",
    "SearchState",
]

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
