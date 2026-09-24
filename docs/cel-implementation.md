# CEL implementation evidence

The implementation in `backend/appchi/cel` uses `cel-expr-python==0.1.3`
and `protobuf==6.33.5`. It implements `appchi-cel-v1` via native parsed protobuf
AST inspection, a restricted typed IR, presence lowering, native checked CEL
compilation and native evaluation. Elasticsearch predicates derive from the same
typed IR. There is no Python expression evaluator or alternate CEL runtime.

The public entrypoint is `compile_expression(source, rule=False)`. The returned
immutable definition supports `evaluate(alert, evaluated_at)`,
`to_elasticsearch(evaluated_at)` and `scoped_query(tenant_id, evaluated_at,
include_suppressed=False)`. Evaluation inputs are managed catalog dictionaries;
timestamp values accept timezone-aware datetimes or the specified RFC3339 strings.
The caller supplies a single PostgreSQL-captured snapshot instant. Compilation
runs in a disposable spawned process under a one-second deadline and reports
unavailability on timeout/crash/dependency failure. It never converts unavailable
evaluation into false. Only the lowered checked program is executed.

Supported constructs include boolean composition and boolean fields, approved
scalar equality/order/membership, nullable membership, literal string methods,
presence, incident UUID membership, and fixed/relative microsecond timestamps.
Rule mode enforces the separate field whitelist and forbids `now()`. Syntax,
size, AST node/depth, literal list and type limits are checked before execution.
Validation errors retain native source positions on IR nodes. The compiler
rejects nested arithmetic, regex, collection macros, indexing, dynamic labels,
field comparisons, unknown methods, floating/unsigned numbers and implicit
coercion. Parsed expressions are inspected only, never evaluated.

`to_elasticsearch` intentionally returns the CEL predicate, suitable for a
larger query builder. Request handlers must add mandatory tenant/live/suppression
constraints; `scoped_query` provides those constraints. Time field mappings must
be signed epoch-microsecond longs. `timestamp` aliases `last_received_at`.
String mappings must preserve exact Unicode values and use a wildcard mapping
for the full message maximum. Queries escape literal wildcard characters.
This module neither creates an Elasticsearch index nor authorizes tenants.

The AST schema is vendored from
[cel-spec commit 40a3c9007a9305d1f2638d5f538a4e011732cace](https://github.com/cel-expr/cel-spec/blob/40a3c9007a9305d1f2638d5f538a4e011732cace/proto/cel/expr/syntax.proto),
with its Apache-2.0 notice retained. `syntax_pb2.py` was generated using
`grpcio-tools==1.78.0` (Python protobuf gencode 6.31.1). The generated schema is
required because the native wheel serializes `cel.expr.ParsedExpr` inside a
protobuf `Any` but does not install corresponding Python descriptors. Generator
and googleapis-common-protos packages are not runtime dependencies.

## Qualification boundaries

The executed tests cover Windows CPython 3.13 and the native 0.1.3 wheel. This is
not an OpenShift/Linux ABI qualification or proof of Elasticsearch equivalence.
An actual Elasticsearch conformance run, supported Linux image build, compiler
load/memory measurement and authoritative-clock health integration remain
required. The expression object lazily retains its checked native program in
the owning process; there is no application-level compiler cache in this module.
Any future authorized saved-resource cache must include resource revision,
tenant and profile identity and enforce its qualified memory allocation.

`rule_cost_upper_bound` exposes deterministic AST-plus-comparison work with
catalog maximum string bytes and conservative substring work, versioned as
`appchi-cel-cost-v1`. It does not establish a qualified budget. Automatic-query
readiness must remain disabled until the separate measured expression and
aggregate rule/group/evidence budgets are supplied and enforced by the caller.
No live service throughput, fault-recovery or production readiness is claimed.
