# CEL implementation evidence

The implementation in `backend/appchi/cel` uses `cel-expr-python==0.1.3`
and `protobuf==6.33.5`. It implements `appchi-cel-v1` via native parsed protobuf
AST inspection, a restricted typed IR, presence lowering, native checked CEL
compilation and native evaluation. Elasticsearch predicates derive from the same
typed IR. There is no Python expression evaluator or alternate CEL runtime.

The public entrypoint is `compile_expression(source, rule=False, reuse=False)`. The returned
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
the owning process. The compiler caches described below key only on profile,
mode and source text. Checked output and native programs are pure functions of
those inputs, and evaluation data is passed per call, so tenants can share
entries without sharing alert data. Any future saved-resource cache that holds
tenant data or results must include resource revision, tenant and profile
identity and enforce its qualified memory allocation.

## Compilation caches and reuse

Two least-recently-used caches, each bounded by `APPCHI_CEL_CACHE_ENTRIES`
(default 4096, accepted 1–65536):

- Checked data, per process: the compiler child's output for `(source, rule)`.
  A miss starts a spawned compiler process under the one-second deadline. A hit
  needs no process. Concurrent misses of one key share one compilation.
- Reusable programs, per thread: `reuse=True` returns this thread's instance
  with its native handle already built. Handles are never shared between
  threads.

Which callers reuse:

- The correlation worker's `prepare_tenant` and maintenance `compile_catalog`
  pass `reuse=True`. They evaluate the same programs for many alerts and
  recompile every enabled expression of a tenant on each turn.
- Product API alert, incident and admin mutation handlers prepare inline
  through `prepare_for_tenant`, so they reuse too: `compile_catalog`, and with
  correlation enabled `prepare_tenant`. They run on the server threadpool, and
  each thread keeps its own program cache.
- Test, validation, search, count and configuration save handlers do not.
  Search, count and validation handlers only build Elasticsearch queries and
  never build a native handle. Configuration saves compile to validate and
  persist the definition: correlation rule create, replace and enable,
  maintenance window saves and deletion, and preset and dashboard saves. Rule
  and maintenance test handlers evaluate once per request; building that handle
  took about 0.4 ms when measured. Reuse there would retain each
  request-supplied expression in every server thread, at about 27 KiB per
  warmed program.
- The processor's cutover check reads only fields, and the indexer probe
  evaluates one instance many times, which builds its handle once.

Size the setting per process above the distinct expressions that process
cycles through. A cyclic working set larger than an LRU misses on every access,
and every checked miss starts a compiler process.

- Correlation worker: the distinct condition sources of the enabled rules of
  every tenant it serves, plus their active maintenance segment expressions.
  At most 10 conditions per rule, so 50 tenants with 50 rules each can need
  up to 25,000 entries plus 1,000 for 20 maintenance windows each. The 4096
  default covers about 1.2 distinct conditions per rule at that scale.
- Processor (inline maintenance and correlation preparation): the same terms for
  the tenants on its partitions.
- Product API, checked data: feed, preset, dashboard and count expressions in
  active use, plus the mutation working set below. Every distinct
  request-supplied expression is retained up to the bound.
- Product API, programs: per thread, the maintenance segments and correlation
  conditions of the tenants whose alerts and incidents that thread mutates.
  Requests land on any thread of the threadpool (40 by default with anyio), so
  each thread converges on the whole mutated-tenant working set. Program memory
  is therefore up to `threads × min(working set, entries) × 27 KiB`: about
  108 MiB per thread and 4.2 GiB for 40 threads when the 4096 bound is full.
  The default suits the API only while the mutated-tenant working set stays in
  the hundreds of expressions. Above that, set a lower bound for the API,
  accepting some misses there, rather than raising it. One setting bounds both
  caches, so lowering it also shrinks the API's checked cache. The API has no
  setting for its threadpool size; changing it would need an API change.

Measured on Windows CPython 3.13 with `cel-expr-python` 0.1.3, for a
three-clause expression: about 4.4 KiB per checked entry and about 27 KiB per
warmed program. Long sources cost more. A full cache therefore holds about
`entries × 4.4 KiB` per process plus `entries × 27 KiB` per thread that uses
reuse. These figures are not a qualified memory allocation.

An eviction logs `cel_cache_evicting` with the cache kind (`checked` or
`programs`), the capacity and the total evictions, at most once a minute per
kind and never with source text. Repeated warnings mean the working set exceeds
the setting. Raise it, or spread tenants across more workers.

A cold miss pays process start, module import and the compile itself. On a
12-core Windows development machine an idle miss took 0.35–0.85 s (two runs:
medians about 0.4 s and 0.6 s, maximum 0.84 s); process start and module
import were most of that. With every core busy, 12 of 12 misses
overran the one-second deadline. The design contract asks only for one-second
compiler jobs in a replaceable worker process (alert history technical
supplement, section 5). Whether and how to replace the per-miss process is an
open decision. See the design register entry "CEL cold
compilation process" of 2026-10-21.

`rule_cost_upper_bound` exposes deterministic AST-plus-comparison work with
catalog maximum string bytes and conservative substring work, versioned as
`appchi-cel-cost-v1`. It does not establish a qualified budget. Automatic-query
readiness must remain disabled until the separate measured expression and
aggregate rule/group/evidence budgets are supplied and enforced by the caller.
No live service throughput, fault-recovery or production readiness is claimed.
