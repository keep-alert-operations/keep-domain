"""Optional capacity-profile budgets: an unset budget is unlimited (REV-39)."""

from keep.shared.errors import unavailable

# The largest integer every consumer handles exactly: PostgreSQL bigint limits
# computed as budget + 1, and JSON clients. Comparisons treat it as unlimited.
UNLIMITED = 9_007_199_254_740_991


def budget(section, name):
    """Return the configured positive integer, or UNLIMITED when it is unset."""
    if not section or section.get(name) is None:
        return UNLIMITED
    value = section[name]
    if type(value) is not int or not 1 <= value <= UNLIMITED:
        raise unavailable("capacity_profile_invalid")
    return value
