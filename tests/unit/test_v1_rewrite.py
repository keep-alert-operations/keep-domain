"""Position-based CEL rewriting for the REV-77 conversion."""

import pytest

from keep.cel import compile_expression
from keep.cel.v1_rewrite import Unprovable, rename_field, rewrite


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'component == "db" && severity in ["critical","high"]',
            'object == "db" && severity in ["error","major"]',
        ),
        ('alert.component != "x"', 'alert.object != "x"'),
        ('has(alert.component) && alert . component == "y"', 'has(alert.object) && alert . object == "y"'),
        ('"critical" == severity || severity != \'high\'', '"error" == severity || severity != \'major\''),
        ('alert.severity == "critical"', 'alert.severity == "error"'),
        ('severity == "warning" && has(alert.severity)', 'severity == "warning" && has(alert.severity)'),
        (
            'message.contains("component") && message == "critical"',
            'message.contains("component") && message == "critical"',
        ),
        ('message == "é😀"\n  || component == "ü"', 'message == "é😀"\n  || object == "ü"'),
        ('!(severity == "high") && components == "x"', '!(severity == "major") && components == "x"'),
    ],
)
def test_rewrite_edits_only_proven_positions(source, expected):
    """Requirements: REV-77; plan A5 (definitions converted by parse positions)."""
    result = rewrite(source)
    assert result.source == expected
    assert result.changed == (source != expected)


def test_rewritten_expressions_compile_in_their_context():
    """Requirements: REV-77; plan A5."""
    result = rewrite('component == "db" && severity in ["critical", "high"]')
    for rule in (False, True):
        program = compile_expression(result.source, rule=rule)
        assert program.evaluate({"object": "db", "severity": "major"}, _now())


@pytest.mark.parametrize(
    "source",
    [
        'string(severity).startsWith("c")',
        "severity == component",
        'severity in ["critical"] + ["high"]',
        "has(component)",
        'severity == r"critical"',
    ],
)
def test_unprovable_expressions_are_refused(source):
    """Requirements: REV-77; plan A5 (unconvertible expressions are listed)."""
    with pytest.raises(Unprovable):
        rewrite(source)


def test_reverse_restores_the_old_words():
    """Requirements: REV-77; plan A10 (rollback)."""
    source = 'object == "db" && severity in ["error", "major"] && has(alert.object)'
    back = rewrite(source, reverse=True)
    assert back.source == 'component == "db" && severity in ["critical", "high"] && has(alert.component)'
    assert rewrite(back.source).source == source
    assert not rewrite(back.source, reverse=True).changed
    assert rename_field("component") == "object" and rename_field("object") == "object"
    assert rename_field("object", reverse=True) == "component"


def _now():
    from datetime import UTC, datetime

    return datetime(2026, 11, 18, tzinfo=UTC)
