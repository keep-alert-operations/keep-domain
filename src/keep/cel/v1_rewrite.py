"""Rewrite saved CEL between the old v1 words and v1 as sent (REV-77).

The rewriter parses with the native CEL parser and edits only the source
positions the parse tree proves: references to `component` (bare or
`alert.component`, also inside `has()`) become `object`, and string literals
compared with `severity` through `==`, `!=` or an `in [...]` list map critical to
error and high to major. `reverse=True` does the opposite. Other text, string
literals that merely contain a field name among it, is never touched. Any use of
`severity` that is not such a comparison (or `has()`) cannot be proven safe, and
the expression is reported unchanged with a reason. The caller recompiles the
result with the definition's own profile and context.
"""

from __future__ import annotations

from dataclasses import dataclass

from keep.alerts.v1_native import TO_LEGACY, TO_SENT


class Unprovable(ValueError):
    """The expression has a use the rewriter cannot prove safe."""


@dataclass(frozen=True)
class Rewrite:
    source: str
    changed: bool


def _parse(source: str):
    from cel_expr_python import cel
    from google.protobuf.any_pb2 import Any as ProtoAny

    from .syntax_pb2 import ParsedExpr

    try:
        parsed = ProtoAny.FromString(cel.NewEnv().compile(source, disable_check=True).serialize())
    except Exception:
        raise Unprovable("cel_parse_failed") from None
    if parsed.type_url != "type.googleapis.com/cel.expr.ParsedExpr":
        raise Unprovable("cel_parse_failed")
    return ParsedExpr.FromString(parsed.value)


def _skip_space(source: str, index: int) -> int:
    while index < len(source) and source[index] in " \t\r\n":
        index += 1
    return index


class _Editor:
    def __init__(self, source: str, positions: dict, reverse: bool):
        self.source, self.positions = source, positions
        self.fields = ("object", "component") if reverse else ("component", "object")
        self.values = TO_LEGACY if reverse else TO_SENT
        self.edits: list[tuple[int, int, str]] = []

    def at(self, expr) -> int:
        if expr.id not in self.positions:
            raise Unprovable("cel_position_missing")
        return self.positions[expr.id]

    def expect(self, index: int, text: str):
        if self.source[index : index + len(text)] != text:
            raise Unprovable("cel_position_mismatch")

    def reference(self, expr) -> str | None:
        """The field a bare or `alert.` reference names, recording a rename."""
        kind = expr.WhichOneof("expr_kind")
        if kind == "ident_expr":
            name = expr.ident_expr.name
            if name == self.fields[0]:
                start = self.at(expr)
                self.expect(start, name)
                self.edits.append((start, start + len(name), self.fields[1]))
            return name
        if kind == "select_expr" and expr.select_expr.operand.WhichOneof("expr_kind") == "ident_expr":
            operand = expr.select_expr.operand
            if operand.ident_expr.name != "alert":
                return None
            name = expr.select_expr.field
            if name == self.fields[0]:
                start = self.at(operand)
                self.expect(start, "alert")
                index = _skip_space(self.source, start + len("alert"))
                self.expect(index, ".")
                index = _skip_space(self.source, index + 1)
                self.expect(index, name)
                self.edits.append((index, index + len(name), self.fields[1]))
            return name
        return None

    def literal(self, expr):
        """Map one severity string literal written plainly as "…" or '…'."""
        if expr.WhichOneof("expr_kind") != "const_expr":
            raise Unprovable("severity_compared_with_non_literal")
        if expr.const_expr.WhichOneof("constant_kind") != "string_value":
            raise Unprovable("severity_compared_with_non_string")
        value = expr.const_expr.string_value
        if value not in self.values:
            return
        start = self.at(expr)
        quote = self.source[start : start + 1]
        if quote not in ('"', "'") or self.source[start : start + len(value) + 2] != (
            quote + value + quote
        ):
            raise Unprovable("severity_literal_form")
        self.edits.append((start + 1, start + 1 + len(value), self.values[value]))

    def visit(self, expr):
        kind = expr.WhichOneof("expr_kind")
        if kind in ("ident_expr", "select_expr"):
            name = self.reference(expr)
            if name == "severity" and not (kind == "select_expr" and expr.select_expr.test_only):
                raise Unprovable("severity_use_not_provable")
            if kind == "select_expr" and name is None:
                self.visit(expr.select_expr.operand)
            return
        if kind == "list_expr":
            for element in expr.list_expr.elements:
                self.visit(element)
            return
        if kind == "struct_expr":
            for entry in expr.struct_expr.entries:
                if entry.HasField("map_key"):
                    self.visit(entry.map_key)
                self.visit(entry.value)
            return
        if kind == "comprehension_expr":
            raise Unprovable("cel_comprehension")
        if kind != "call_expr":
            return
        call = expr.call_expr
        args = list(call.args)
        if call.function in ("_==_", "_!=_") and len(args) == 2 and not call.HasField("target"):
            names = [self.reference_name(arg) for arg in args]
            if "severity" in names:
                index = names.index("severity")
                self.literal(args[1 - index])
                self.reference(args[index])
                return
        if call.function == "@in" and len(args) == 2 and not call.HasField("target"):
            if self.reference_name(args[0]) == "severity":
                if args[1].WhichOneof("expr_kind") != "list_expr":
                    raise Unprovable("severity_membership_not_a_list")
                for element in args[1].list_expr.elements:
                    self.literal(element)
                return
        if call.HasField("target"):
            self.visit(call.target)
        for arg in args:
            self.visit(arg)

    @staticmethod
    def reference_name(expr) -> str | None:
        kind = expr.WhichOneof("expr_kind")
        if kind == "ident_expr":
            return expr.ident_expr.name
        if (
            kind == "select_expr"
            and not expr.select_expr.test_only
            and expr.select_expr.operand.WhichOneof("expr_kind") == "ident_expr"
            and expr.select_expr.operand.ident_expr.name == "alert"
        ):
            return expr.select_expr.field
        return None

    def result(self) -> str:
        text = self.source
        last = None
        for start, end, replacement in sorted(set(self.edits), reverse=True):
            if last is not None and end > last:
                raise Unprovable("cel_overlapping_edits")
            text = text[:start] + replacement + text[end:]
            last = start
        return text


def rewrite(source: str, *, reverse: bool = False) -> Rewrite:
    """Return the rewritten source, or raise Unprovable with a reason code."""
    ast = _parse(source)
    editor = _Editor(source, dict(ast.source_info.positions), reverse)
    editor.visit(ast.expr)
    text = editor.result()
    return Rewrite(text, text != source)


def rename_field(name: str, *, reverse: bool = False) -> str:
    """Rename one column, sort or grouping field."""
    old, new = ("object", "component") if reverse else ("component", "object")
    return new if name == old else name
