"""Versioned Unicode token semantics shared by projection and text queries."""

from functools import lru_cache
import unicodedata

from appchi.shared.errors import AppError

UNICODE_VERSION = "15.1.0"
TOKENIZER_PROFILE = "appchi-text-unicode15.1-v1"


def _check_unicode():
    if unicodedata.unidata_version != UNICODE_VERSION:
        raise AppError("tokenizer_profile_unavailable", "Unsupported Unicode data version", 503)


@lru_cache(maxsize=1)
def max_query_token_bytes() -> int:
    _check_unicode()
    # Derived from the pinned profile, including supplementary scalar values.
    widest = max(
        len(chr(n).casefold().encode("utf-8")) for n in range(0x110000) if not 0xD800 <= n <= 0xDFFF
    )
    return 256 * widest


def tokens(value: str) -> set[str]:
    _check_unicode()
    output, current = set(), []
    for char in value:
        if char == "_" or unicodedata.category(char)[0] in {"L", "M", "N"}:
            current.append(char)
        elif current:
            output.add("".join(current).casefold())
            current = []
    if current:
        output.add("".join(current).casefold())
    return output


def query_tokens(q: str | None) -> list[str]:
    if q is None or q == "":
        return []
    if not isinstance(q, str) or len(q) > 256:
        raise AppError("invalid_query", "q must contain at most 256 code points")
    result = sorted(tokens(q))
    if not result:
        raise AppError("invalid_query", "q must contain a searchable token")
    return result


def source_tokens(values: list[str]) -> list[str]:
    limit = max_query_token_bytes()
    return sorted(
        {word for value in values for word in tokens(value) if len(word.encode("utf-8")) <= limit}
    )
