"""Native CEL AST -> restricted typed IR -> guarded CEL and parameterized ES.

Parsing and checked compilation run in a disposable process with a one-second
wall-clock deadline. No parsed-only expression is ever evaluated.
"""

from __future__ import annotations

from functools import lru_cache

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import multiprocessing
import re
from typing import Any
from uuid import UUID

from .catalog import FIELDS, RULE_FIELDS, storage_name
from appchi.alerts.presentation import display_status

PROFILE = "appchi-cel-v1"
COST_MODEL = "appchi-cel-cost-v1"
MAX_SOURCE_BYTES = 16384
MAX_AST_NODES = 256
MAX_DEPTH = 32
MAX_LIST_MEMBERS = 100
COMPILE_TIMEOUT_SECONDS = 1.0
BOOLEAN_OPERATORS = {"_&&_": "and", "_||_": "or", "!_": "not"}
COMPARISON_OPERATORS = {
    "_==_": "eq",
    "_!=_": "ne",
    "_<_": "lt",
    "_<=_": "le",
    "_>_": "gt",
    "_>=_": "ge",
}
TIME_OPERATORS = {"_+_": "+", "_-_": "-"}
MEMBERSHIP_OPERATOR = "@in"
STRING_METHODS = ("startsWith", "endsWith", "contains")
TIME_LITERAL_FUNCTIONS = ("timestamp", "duration")
NOW_FUNCTION = "now"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class CELValidationError(ValueError):
    def __init__(self, message: str, position: int | None = None):
        super().__init__(message)
        self.position = position


class CELUnavailableError(RuntimeError):
    """Runtime/compiler unavailable; never interpret this as a nonmatch."""


@dataclass(frozen=True)
class IR:
    op: str
    kind: str
    value: Any = None
    args: tuple[IR, ...] = ()
    position: int | None = None


def epoch_us(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CELValidationError("Query timestamps must be timezone-aware datetimes")
    try:
        delta = value.astimezone(timezone.utc) - EPOCH
    except (OverflowError, ValueError) as exc:
        raise CELValidationError("Timestamp outside years 0001–9999") from exc
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def timestamp(text: str) -> int:
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        text,
    ):
        raise CELValidationError(
            "Timestamp requires RFC3339 with explicit offset and microsecond precision"
        )
    if text[-1] != "Z" and (int(text[-5:-3]) > 23 or int(text[-2:]) > 59):
        raise CELValidationError("Invalid timestamp offset")
    try:
        return epoch_us(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except (ValueError, OverflowError) as exc:
        raise CELValidationError("Invalid timestamp") from exc


MIN_TIME = epoch_us(datetime.min.replace(tzinfo=timezone.utc))
MAX_TIME = epoch_us(datetime.max.replace(tzinfo=timezone.utc))


def duration(text: str) -> int:
    match = re.fullmatch(r"(?:([0-9]+)h)?(?:([0-9]+)m)?(?:([0-9]+)(?:\.([0-9]{1,6}))?s)?", text)
    if not match or not text:
        raise CELValidationError("Duration must be nonnegative literal hours/minutes/seconds")
    hours, minutes, seconds, fraction = match.groups()
    total = (int(hours or 0) * 3600 + int(minutes or 0) * 60 + int(seconds or 0)) * 1_000_000
    total += int((fraction or "").ljust(6, "0"))
    if total > 3652500 * 86400 * 1_000_000:
        raise CELValidationError("Duration exceeds 3,652,500 days")
    return total


class Builder:
    def __init__(self, positions: dict, rule: bool):
        self.positions, self.rule, self.nodes = positions, rule, 0

    def build(self, expr, depth: int = 1) -> IR:
        self.nodes += 1
        pos = self.positions.get(expr.id)
        if self.nodes > MAX_AST_NODES or depth > MAX_DEPTH:
            raise CELValidationError("Expression exceeds 256 nodes or depth 32", pos)

        def sub(child):
            return self.build(child, depth + 1)

        kind = expr.WhichOneof("expr_kind")
        if kind == "const_expr":
            const = expr.const_expr
            selected = const.WhichOneof("constant_kind")
            types = {
                "string_value": "string",
                "int64_value": "int",
                "bool_value": "bool",
                "null_value": "null",
            }
            if selected not in types:
                raise CELValidationError(
                    "Only signed integers, strings, booleans and null are literals", pos
                )
            value = None if selected == "null_value" else getattr(const, selected)
            return IR("literal", types[selected], value, position=pos)
        if kind == "ident_expr":
            name = expr.ident_expr.name
            if name not in FIELDS or (self.rule and name not in RULE_FIELDS):
                raise CELValidationError("Only approved alert fields may be referenced", pos)
            return IR("field", FIELDS[name].kind, name, position=pos)
        if kind == "select_expr":
            sel = expr.select_expr
            self.nodes += 1  # the namespace or bare-field identifier is an AST node too
            if self.nodes > MAX_AST_NODES or depth + 1 > MAX_DEPTH:
                raise CELValidationError("Expression exceeds 256 nodes or depth 32", pos)
            if sel.operand.WhichOneof("expr_kind") != "ident_expr":
                raise CELValidationError("Only direct approved field references are allowed", pos)
            operand = sel.operand.ident_expr.name
            # `alert.field` remains accepted for saved expressions. Bare fields
            # are the current syntax; CEL's has() macro represents has(field)
            # as a test-only select over an identifier with an empty field.
            if operand == "alert":
                name = sel.field
            elif sel.test_only and not sel.field and operand in FIELDS:
                name = operand
            else:
                raise CELValidationError("Only direct approved field references are allowed", pos)
            if name not in FIELDS or (self.rule and name not in RULE_FIELDS):
                raise CELValidationError(f"Unsupported field: {name}", pos)
            if sel.test_only and FIELDS[name].kind == "ids":
                raise CELValidationError("has() requires a scalar field", pos)
            return IR(
                "has" if sel.test_only else "field",
                "bool" if sel.test_only else FIELDS[name].kind,
                name,
                position=pos,
            )
        if kind == "list_expr":
            if len(expr.list_expr.elements) > MAX_LIST_MEMBERS or expr.list_expr.optional_indices:
                raise CELValidationError(
                    "Lists permit at most 100 nonoptional literal members", pos
                )
            args = tuple(sub(x) for x in expr.list_expr.elements)
            if (
                any(x.op != "literal" for x in args)
                or len({x.kind for x in args if x.kind != "null"}) > 1
            ):
                raise CELValidationError(
                    "Membership lists must contain homogeneous scalar literals", pos
                )
            return IR("list", "list", args=args, position=pos)
        if kind != "call_expr":
            raise CELValidationError("Unsupported CEL construct", pos)
        call = expr.call_expr
        args = tuple(sub(x) for x in call.args)
        target = sub(call.target) if call.HasField("target") else None
        fn = call.function
        if fn == "has" and target is None and len(args) == 1 and args[0].op == "field":
            if args[0].kind == "ids":
                raise CELValidationError("has() requires a scalar field", pos)
            return IR("has", "bool", args[0].value, args=(args[0],), position=pos)
        if target:
            if (
                fn not in STRING_METHODS
                or target.op != "field"
                or target.kind != "string"
                or len(args) != 1
                or args[0].op != "literal"
                or args[0].kind != "string"
            ):
                raise CELValidationError("Unsupported string method or argument", pos)
            return IR(fn, "bool", args=(target, *args), position=pos)
        if fn in BOOLEAN_OPERATORS:
            if len(args) != (1 if fn == "!_" else 2) or any(x.kind != "bool" for x in args):
                raise CELValidationError("Boolean operators require booleans", pos)
            return IR(BOOLEAN_OPERATORS[fn], "bool", args=args, position=pos)
        if (
            fn in TIME_LITERAL_FUNCTIONS
            and len(args) == 1
            and args[0].op == "literal"
            and args[0].kind == "string"
        ):
            return IR(
                "literal",
                "time" if fn == "timestamp" else "duration",
                (timestamp if fn == "timestamp" else duration)(args[0].value),
                position=pos,
            )
        if fn == NOW_FUNCTION and not args and not self.rule:
            return IR("now", "time", 0, position=pos)
        if (
            fn in TIME_OPERATORS
            and len(args) == 2
            and args[0].kind == "time"
            and args[0].op in {"literal", "now"}
            and args[1].kind == "duration"
            and args[1].op == "literal"
        ):
            if (
                call.args[0].WhichOneof("expr_kind") == "call_expr"
                and call.args[0].call_expr.function in TIME_OPERATORS
            ):
                raise CELValidationError("Nested time arithmetic is not supported", pos)
            offset = args[1].value * (1 if fn == "_+_" else -1)
            result = IR(
                "bound" if args[0].op == "now" else "literal",
                "time",
                args[0].value + offset,
                position=pos,
            )
            if result.op == "literal" and not MIN_TIME <= result.value <= MAX_TIME:
                raise CELValidationError("Time arithmetic outside supported years", pos)
            return result
        if fn == MEMBERSHIP_OPERATOR and len(args) == 2:
            left, right = args
            if (
                right.op == "field"
                and right.kind == "ids"
                and left.op == "literal"
                and left.kind == "string"
            ):
                try:
                    UUID(left.value)
                except ValueError as exc:
                    raise CELValidationError(
                        "Incident membership requires a UUID literal", pos
                    ) from exc
                return IR("member", "bool", args=args, position=pos)
            if left.op != "field" or left.kind == "ids" or right.op != "list":
                raise CELValidationError("Membership requires a scalar field and literal list", pos)
            for item in right.args:
                self.compatible(left, item)
            return IR("in", "bool", args=args, position=pos)
        comparisons = COMPARISON_OPERATORS
        if fn in comparisons and len(args) == 2:
            left, right = args
            op = comparisons[fn]
            if left.op == right.op == "literal":
                if left.kind != right.kind and "null" not in {left.kind, right.kind}:
                    raise CELValidationError("Constant comparison types differ", pos)
                if op in {"eq", "ne"}:
                    equal = left.kind == right.kind and left.value == right.value
                    return IR("literal", "bool", equal if op == "eq" else not equal, position=pos)
                if left.kind == right.kind and left.kind in {"int", "time"}:
                    result = {
                        "lt": left.value < right.value,
                        "le": left.value <= right.value,
                        "gt": left.value > right.value,
                        "ge": left.value >= right.value,
                    }[op]
                    return IR("literal", "bool", result, position=pos)
                raise CELValidationError("Unsupported ordered constant comparison", pos)
            if left.op != "field" and right.op == "field":
                left, right = right, left
                op = {"lt": "gt", "le": "ge", "gt": "lt", "ge": "le"}.get(op, op)
            if left.op != "field" or right.op not in {"literal", "now", "bound"}:
                raise CELValidationError(
                    "Comparisons require a scalar field and compatible literal", pos
                )
            self.compatible(left, right)
            if op not in {"eq", "ne"} and (
                left.kind not in {"int", "time"} or right.kind == "null"
            ):
                raise CELValidationError("Ordered comparisons require integers or timestamps", pos)
            return IR(op, "bool", args=(left, right), position=pos)
        raise CELValidationError(f"Unsupported function or operator: {fn}", pos)

    @staticmethod
    def compatible(left: IR, right: IR):
        spec = FIELDS[left.value]
        if right.kind == "null":
            if not spec.nullable:
                raise CELValidationError(
                    "Null comparison requires a nullable field", right.position
                )
            return
        if left.kind == "enum":
            if right.kind != "string" or right.value not in spec.values:
                raise CELValidationError("Invalid enum literal", right.position)
        elif left.kind != right.kind or left.kind == "ids":
            raise CELValidationError("Literal does not match field type", right.position)


def walk(ir: IR):
    yield ir
    for child in ir.args:
        yield from walk(child)


def literal(value: Any) -> str:
    # CEL Unicode escapes represent scalar values, so do not emit JSON's
    # surrogate-pair escapes for supplementary characters.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def lower(ir: IR, bounds: list[int]) -> str:
    op = ir.op
    if op == "field":
        return "v_" + ir.value
    if op == "has":
        return "p_" + ir.value
    if op == "literal":
        return literal(ir.value)
    if op in {"now", "bound"}:
        bounds.append(ir.value)
        return f"clock_{len(bounds) - 1}"
    if op in {"and", "or"}:
        return f"({lower(ir.args[0], bounds)} {'&&' if op == 'and' else '||'} {lower(ir.args[1], bounds)})"
    if op == "not":
        return f"!({lower(ir.args[0], bounds)})"
    if op == "member":
        return f"({lower(ir.args[0], bounds)} in {lower(ir.args[1], bounds)})"
    left, right = ir.args
    present = "p_" + left.value
    if op == "in":
        parts = [lower(IR("eq", "bool", args=(left, item)), bounds) for item in right.args]
        return "(" + " || ".join(parts) + ")" if parts else "false"
    if right.kind == "null":
        return ("!" if op == "eq" else "") + present
    a, b = lower(left, bounds), lower(right, bounds)
    if op in {"startsWith", "endsWith", "contains"}:
        return f"({present} && {a}.{op}({b}))"
    comparison = {"eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">="}[op]
    if op == "ne":
        return f"(!{present} || {a} != {b})"
    return f"({present} && {a} {comparison} {b})"


def environment(fields: tuple[str, ...], bound_count: int):
    from cel_expr_python import cel

    types = {
        "string": cel.Type.STRING,
        "enum": cel.Type.STRING,
        "bool": cel.Type.BOOL,
        "int": cel.Type.INT,
        "time": cel.Type.INT,
        "ids": cel.Type.List(cel.Type.STRING),
    }
    variables = {"v_" + name: types[FIELDS[name].kind] for name in fields}
    variables.update({"p_" + name: cel.Type.BOOL for name in fields})
    variables.update({f"clock_{i}": cel.Type.INT for i in range(bound_count)})
    return cel.NewEnv(variables=variables)


def _compile_worker(connection, source: str, rule: bool):
    try:
        from cel_expr_python import cel
        from google.protobuf.any_pb2 import Any as ProtoAny
        from .syntax_pb2 import ParsedExpr

        # This parse-only object is inspected and discarded; eval is never called.
        parsed = ProtoAny.FromString(cel.NewEnv().compile(source, disable_check=True).serialize())
        if parsed.type_url != "type.googleapis.com/cel.expr.ParsedExpr":
            raise CELUnavailableError("Unexpected native parsed expression envelope")
        ast = ParsedExpr.FromString(parsed.value)
        builder = Builder(dict(ast.source_info.positions), rule)
        ir = builder.build(ast.expr)
        if ir.kind != "bool":
            raise CELValidationError("Expression must return bool", ir.position)
        fields = tuple(sorted({x.value for x in walk(ir) if x.op in {"field", "has"}}))
        bounds: list[int] = []
        lowered = lower(ir, bounds)
        program = environment(fields, len(bounds)).compile(lowered)
        if program.return_type() != cel.Type.BOOL:
            raise CELUnavailableError("Checked program result is not bool")
        checked = program.serialize()
        if ProtoAny.FromString(checked).type_url != "type.googleapis.com/cel.expr.CheckedExpr":
            raise CELUnavailableError("Native compiler did not return a checked expression")
        connection.send(("ok", ir, fields, tuple(bounds), checked, builder.nodes, lowered))
    except CELValidationError as exc:
        connection.send(("invalid", str(exc), exc.position))
    except (ImportError, CELUnavailableError) as exc:
        connection.send(("unavailable", str(exc)))
    except Exception as exc:
        connection.send(("invalid", str(exc), None))
    finally:
        connection.close()


def time_bound(ir: IR, evaluated_at: datetime) -> Any:
    value = ir.value + epoch_us(evaluated_at) if ir.op in {"now", "bound"} else ir.value
    if ir.kind == "time" and not MIN_TIME <= value <= MAX_TIME:
        raise CELValidationError("Resulting time bound outside supported years", ir.position)
    return value


def negate(query: dict) -> dict:
    return {"bool": {"must_not": [query]}}


def elastic(ir: IR, evaluated_at: datetime) -> dict:
    op = ir.op
    if op == "literal":
        return {"match_all" if ir.value else "match_none": {}}
    if op == "field":
        return {"term": {storage_name(ir.value): True}}
    if op == "has":
        return {
            "exists": {
                "field": "status" if ir.value == "display_status" else storage_name(ir.value)
            }
        }
    if op == "not":
        return negate(elastic(ir.args[0], evaluated_at))
    if op in {"and", "or"}:
        body = {"filter" if op == "and" else "should": [elastic(x, evaluated_at) for x in ir.args]}
        if op == "or":
            body["minimum_should_match"] = 1
        return {"bool": body}
    left, right = ir.args
    if op == "member":
        return {"term": {storage_name(right.value): left.value}}
    name = storage_name(left.value)
    if op == "in":
        return (
            {
                "bool": {
                    "should": [
                        elastic(IR("eq", "bool", args=(left, x)), evaluated_at) for x in right.args
                    ],
                    "minimum_should_match": 1,
                }
            }
            if right.args
            else {"match_none": {}}
        )
    value = time_bound(right, evaluated_at)
    if left.value == "display_status" and op in {"eq", "ne"}:
        if value == "resolved":
            query = {"term": {"status": "resolved"}}
        else:
            assigned = {"exists": {"field": "assignee_id"}}
            query = {
                "bool": {
                    "filter": [
                        {"term": {"status": "firing"}},
                        assigned if value == "acknowledged" else negate(assigned),
                    ]
                }
            }
        return negate(query) if op == "ne" else query
    if op in {"eq", "ne"}:
        query = negate({"exists": {"field": name}}) if value is None else {"term": {name: value}}
        return negate(query) if op == "ne" else query
    if op in {"lt", "le", "gt", "ge"}:
        return {"range": {name: {{"le": "lte", "ge": "gte"}.get(op, op): value}}}
    escaped = value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
    pattern = {
        "startsWith": escaped + "*",
        "endsWith": "*" + escaped,
        "contains": "*" + escaped + "*",
    }[op]
    return {"wildcard": {name: {"value": pattern, "case_insensitive": False}}}


@dataclass(frozen=True)
class CompiledExpression:
    source: str
    ir: IR
    fields: tuple[str, ...]
    bounds: tuple[int, ...]
    checked: bytes = field(repr=False)
    ast_nodes: int = 0
    lowered_source: str = field(default="", repr=False)
    profile: str = PROFILE
    cost_model: str = COST_MODEL
    _program: Any = field(default=None, repr=False, compare=False)

    @property
    def relative(self) -> bool:
        return bool(self.bounds)

    @property
    def rule_cost_upper_bound(self) -> int:
        cost = self.ast_nodes
        for item in walk(self.ir):
            if item.op in {
                "eq",
                "ne",
                "lt",
                "le",
                "gt",
                "ge",
                "startsWith",
                "endsWith",
                "contains",
                "in",
            }:
                left, right = item.args
                candidates = right.args if right.op == "list" else (right,)
                for candidate in candidates:
                    cost += 1
                    if left.kind in {"string", "enum"}:
                        literal_bytes = len(str(candidate.value).encode("utf-8"))
                        work = FIELDS[left.value].max_bytes + literal_bytes
                        if item.op == "contains":
                            work = (
                                FIELDS[left.value].max_bytes * max(literal_bytes, 1) + literal_bytes
                            )
                        cost += work
        return cost

    def evaluate(self, alert: dict, evaluated_at: datetime) -> bool:
        epoch_us(evaluated_at)
        data = {}
        defaults = {"string": "", "enum": "", "bool": False, "int": 0, "time": 0, "ids": []}
        for name in self.fields:
            spec = FIELDS[name]
            value = (
                display_status(alert)
                if name == "display_status"
                else alert.get(name, alert.get(storage_name(name)))
            )
            if value is None and not spec.nullable:
                raise CELValidationError(f"Required alert field missing: {name}")
            data["p_" + name] = value is not None
            if value is not None:
                if spec.kind == "time":
                    value = timestamp(value) if isinstance(value, str) else epoch_us(value)
                elif spec.kind in {"string", "enum"}:
                    if not isinstance(value, str) or len(value.encode("utf-8")) > spec.max_bytes:
                        raise CELValidationError(f"Invalid string field: {name}")
                    if spec.values and value not in spec.values:
                        raise CELValidationError(f"Invalid enum field: {name}")
                elif spec.kind == "bool" and type(value) is not bool:
                    raise CELValidationError(f"Invalid boolean field: {name}")
                elif spec.kind == "int" and (
                    type(value) is not int or not -(2**63) <= value < 2**63
                ):
                    raise CELValidationError(f"Invalid integer field: {name}")
                elif spec.kind == "ids" and (
                    not isinstance(value, list) or any(not isinstance(x, str) for x in value)
                ):
                    raise CELValidationError(f"Invalid membership field: {name}")
            data["v_" + name] = defaults[spec.kind] if value is None else value
        for i, offset in enumerate(self.bounds):
            data[f"clock_{i}"] = time_bound(IR("bound", "time", offset), evaluated_at)
        if self._program is None:
            try:
                object.__setattr__(
                    self,
                    "_program",
                    environment(self.fields, len(self.bounds)).deserialize(self.checked),
                )
            except Exception as exc:
                raise CELUnavailableError("Checked native runtime unavailable") from exc
        try:
            result = self._program.eval(data=data).value()
        except Exception as exc:
            raise CELUnavailableError("Native CEL evaluation failed") from exc
        if type(result) is not bool:
            raise CELUnavailableError("Native CEL evaluation did not return a boolean")
        return result

    def to_elasticsearch(self, evaluated_at: datetime) -> dict:
        """Return only the CEL predicate; caller must enforce tenant/live/suppression."""
        epoch_us(evaluated_at)
        return elastic(self.ir, evaluated_at)

    def scoped_query(
        self, tenant_id: str, evaluated_at: datetime, *, include_suppressed: bool = False
    ) -> dict:
        filters = [
            {"term": {"tenant_id": tenant_id}},
            {"term": {"deleted": False}},
            self.to_elasticsearch(evaluated_at),
        ]
        if not include_suppressed:
            filters.append({"term": {"suppressed": False}})
        return {"bool": {"filter": filters}}


def compile_expression(source: str, *, rule: bool = False) -> CompiledExpression:
    if not isinstance(source, str):
        raise CELValidationError("Expression source must be a string")
    try:
        encoded = source.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CELValidationError("Expression contains invalid Unicode") from exc
    if not encoded or len(encoded) > MAX_SOURCE_BYTES:
        raise CELValidationError("Expression must contain 1–16384 UTF-8 bytes")
    ir, fields, bounds, checked, nodes, lowered = _compile_checked(source, rule)
    # Native evaluation handles are instance-local; cached checked data never shares
    # mutable native runtime state between concurrent callers.
    return CompiledExpression(source, ir, fields, bounds, checked, nodes, lowered)


@lru_cache(maxsize=256)
def _compile_checked(source: str, rule: bool):
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_compile_worker, args=(send, source, rule), daemon=True)
    process.start()
    send.close()
    try:
        if not receive.poll(COMPILE_TIMEOUT_SECONDS):
            raise CELUnavailableError("CEL compiler exceeded one-second deadline")
        try:
            message = receive.recv()
        except EOFError as exc:
            raise CELUnavailableError("CEL compiler worker crashed") from exc
        if message[0] == "invalid":
            raise CELValidationError(message[1], message[2])
        if message[0] == "unavailable":
            raise CELUnavailableError(message[1])
        _, ir, fields, bounds, checked, nodes, lowered = message
        return ir, fields, bounds, checked, nodes, lowered
    finally:
        receive.close()
        process.join(timeout=0.02)
        if process.is_alive():
            process.terminate()
            process.join(timeout=0.1)
