# Maintenance implementation checkpoint

The implementation includes PostgreSQL-backed maintenance CRUD, schedule
conversion, immutable revision/control/segment proof, protected deletion, a
complete-history suppression adapter and fenced fan-out primitives. The normative
contract remains [maintenance operations](../spec-maintenance-operations.md).
Capability `maintenance` remains false until shared transaction, worker,
correlation and search visibility paths are integrated and qualified. Isolated
component tests do not establish that the whole workflow is enabled.

## Configuration and API

Mount `appchi.maintenance.routes.router`. Routes use ordinary authenticated
sessions, current tenant authorization, Origin/CSRF checks for POST/PATCH/DELETE,
strict models, expected revisions, command receipts and the tenant coordinator.
There is no maintenance-specific login or authorization bypass.

Under `/api/tenants/{tenant_id}` the implementation exposes:

- `POST /maintenance`, `PATCH /maintenance/{id}`, enable/disable commands and
  `DELETE /maintenance/{id}`. Edits explicitly distinguish metadata, timezone
  display, and schedule/expression edits. Unchanged content creates no revision,
  control, segment, history record or fan-out job.
- `GET /maintenance`, detail, history/revision and affected-alert pages. Filters
  cover name, enabled intent, phase and UTC overlap. Encrypted keyset cursors are
  bound to session, tenant, query, deployment epoch and expiry.
- `POST /maintenance/validate`, `POST /maintenance/test`, and `GET /timezones`.
  Viewers may validate/test without saving. A current CEL match is distinct from
  proof of a qualifying historical transition.

Mutation requires explicit measured `app.state.profile['maintenance']` allocations
`max_overlap` and `max_work_bytes`. Overlap reservations include disabled and future
windows and serialize under the coordinator. Definition bytes include UTF-8 CEL
and reason; these do not qualify reducer throughput. Duplicate names are accepted.
Deletion additionally requires `app.state.recovery_store`. Intent/final/cancel
proof uses distinct durable UUIDs. Failed external final acknowledgment leaves a
logically deleted resource and resumable job; `resume_delete` uses the same final
proof ID and receipt. No false success is returned. Missing storage does not start
deletion.

`timezones.py` loads pinned `tzdata==2025.2` directly rather than host timezone
files. It rejects DST gaps, requires first/second for ambiguous times, verifies
UTC/year bounds and retains accepted zone/offset/fold evidence. Timezone-only
edits preserve UTC. Start/expression become irreversibly locked at the start.
End extension retains original activation; disable/enable starts a new activation
and cannot backfill an existing matching alert.

## Durable proof and transactional integration

Migrations `0009_maintenance.sql` and `0011_maintenance_processing.sql` add windows,
revisions, controls, segments, jobs, causes, per-alert input journals/checkpoints,
32-way alert-ID hash-partitioned cause/union histories, and qualifier effects.
Tenant tables have forced RLS and compound tenant foreign keys. The migration does
not invent historical input for existing alerts. Missing baseline blocks reduction.

`processing.py` exposes these integration points:

1. `record_input(conn, before, after, effective_time, original_order, cause,
   processing_now)` persists a stable input UUID and fingerprint. Call on every
   source receipt, including repeats, and every semantic rule-field manual/system
   transition, even while maintenance is disabled. Creation explicitly has
   `before=None` and an already-inserted alert identity. Use actual source receipt
   time/order; allocate shared tenant order for manual/system actions under the
   coordinator. Derived suppression/revisions do not affect the fingerprint.
2. `prepare_catalog(database, tenant_id, max_work=..., max_inputs=...,
   max_segments=...)` reads a consistent catalog and compiles shared native CEL
   outside write locks. Caller supplies qualified positive allocations. Generation
   mismatch causes retry; unknown profile/digest fails closed.
3. `record_transition(..., catalog=...)` records/reduces and returns
   `(adjusted_after, Effects)`. `reconcile_alert(conn, current, processing_now,
   catalog=...)` replays without inventing input. Callers hold coordinator → sorted
   window/context/incident locks → alert lock, drain earlier source work outside
   source order, and commit revision/aggregate/history/correlation/projection/live
   work atomically. The adapter itself changes neither semantic revisions nor
   projection versions.
4. `Effects` reports suppression/history changes, stable final-unsuppression
   qualifier IDs with original effective times, withdrawn qualifier IDs, and proof
   digest. Correlation must consume/withdraw these before decisions. Historical
   qualifiers are not new current-time events. Derived-only fan-out publication
   must not insert today's rule snapshot at an earlier end/control boundary.
5. `derive_current(conn, current, at)` is read-only and returns current suppression
   plus materialization-pending status from trusted causes and live boundaries.
   Missing checkpoints fail closed. Decisions still require transactional replay.

`temporal.reduce_alert` retains source/control order and requires explicit creation
plus the complete before/after chain. Scheduled ends are exclusive and precede
equal-time source input. New alerts, refiring and false-to-true may create causes;
activation and true-to-true repeats do not. Source-v2 and maintenance causes are
independent. Overlaps form an OR union. Delayed processing records historical
intervals at original boundary times without rewriting later source fields.
Stable keys and SQL uniqueness make replay idempotent. Unknown input, missing
predecessors, allocation exhaustion and CEL failure roll back effects.

## Scheduler integration

`claim_due(database, tenant_id)` acquires a fenced ten-second lease. Scheduled ends
verify expected end; stale jobs become obsolete. A valid end publishes one durable
invalidation generation at its original end time. Prepare catalog after claiming.

`step_job(database, lease, catalog, lock_alert=..., publish=...)` processes at most
one complete alert per transaction and returns `processed`, `complete` or `stale`.
The mandatory lock callback obtains context/incident locks before the alert and
rejects earlier pending source work. The mandatory publisher commits revisions,
aggregate consequences, correlation effects and projection/live work. Publication
failure rolls back cause/checkpoint and cursor together. Each step renews its
lease; completion saves the projection sequence required for search visibility.
Late source insertion independently reconciles known controls behind a completed
cursor.

Host worker scans once per second, continues/renews within three seconds, yields
after 100 alerts or 100 ms between complete steps, and bounds retries.
`finish_failed_job(..., proof_blocked=True)` marks fenced proof failures for repair
without clearing causes. Temporary source/catalog conflicts release the lease
with `proof_blocked=False`. These primitives do not establish hosting worker
latency/fairness. No network calls belong in callbacks.

`runtime.py` supplies that local worker bridge with correlation context and linked
incident locks, pending-source guard, common alert store and projection/live
publisher. `prepare_for_tenant` requires a qualified profile with explicit positive
integer `maintenance_max_work`, `maintenance_max_inputs` and
`maintenance_max_segments`. `apply_transition` recomputes semantic revisions after
reduction, preserving unchanged source repeats and independent note revisions.
`Effects.input_suppressed` records original input-boundary eligibility separately
from the current materialized boolean.

Shared source processing, alert commands/bulk/notes and alert/incident inactivity
now invoke the bridge. Alert detail derives immediate suppression read-only.
Migration `0014_maintenance_effect_outbox.sql` retains append-only qualifier
activation/withdrawal events with exact boundary snapshots, original order/time,
scheduled flag, stable qualifier UUID and correction links. Its consumer must
merge these events with `correlation_journal` by shared tenant `change_order` and
recheck current authoritative state. History-only publication never fabricates a
new source input at an old boundary. Closing the maintenance gate after a tenant
has a retained timeline blocks unsafe writes instead of silently clearing causes.

## Executed checks and remaining gates

Local evidence: all 52 maintenance tests passed together: 27 timezone/temporal,
11 CRUD real-PostgreSQL and 14 processing/runtime real-PostgreSQL tests. They cover native CEL, DST, concurrent
expected revisions/capacity, nonowner API-role RLS, no-op revisions, protected
delete resume, delayed receipts after disable, source/window overlap, no backfill,
false-to-true reopening, replay, missing proof/budget rollback, gate-false baseline
recording, stale leases, atomic publisher failure, one-time end invalidation,
real source admission/processing, manual acknowledgment/no-op/note revisions,
inactivity and real projection publication. The existing ingestion/product/
inactivity/security regression suite also passed 21 tests; one OS temporary-folder
permission failure was rerun successfully using a workspace test directory.
Identity, timestamps, recovery storage and publisher callbacks are controlled
fixtures; they do not qualify deployed OIDC, LDAP, storage or the shared worker.

After adding input-head warmup and protected-delete rechecks, the targeted real
PostgreSQL regression passed 40 tests: 3 warmup, 15 maintenance CRUD, 14 temporal
processing/runtime and 8 identity cleanup cases. These include permission or gate
changes during external intent, invalid cancel acknowledgments, checkpoint
invalidation by new source receipts, exact replay and missing-baseline refusal.

Run against an isolated PostgreSQL cluster with a test identity permitted to
create/drop dedicated test databases:

```powershell
$env:APPCHI_MAINTENANCE_TEST_ADMIN_URL = '<isolated PostgreSQL test admin DSN>'
backend/.venv/Scripts/python.exe -m pytest backend/tests/unit/test_maintenance_timezones.py backend/tests/unit/test_maintenance_temporal.py backend/tests/unit/test_maintenance_repository.py backend/tests/unit/test_maintenance_processing.py backend/tests/unit/test_maintenance_warmup.py -q
backend/.venv/Scripts/ruff.exe check backend/appchi/maintenance backend/tests/unit/test_maintenance*.py
```

Remaining before enablement: manual incident relationship hooks; hosted scheduler
qualification; temporal correlation effect consumption and
withdrawal; search/count suppression-generation proof; retention pins and cleanup;
reviewed repair/import for existing alerts without baseline and qualified atomic
activation after checkpoint warmup; frontend integration;
and measured capacity/latency acceptance. Input journals currently retain whole
proof; allocation limits block rather than discard it. Safe compacted checkpoints
and retention remain necessary for long-lived alerts. No company-service capacity
or five-second visibility result is claimed.

## Offline warmup and input fences

Migration `0021_maintenance_input_heads.sql` adds a durable input revision per
alert, initializes it from retained journal rows and invalidates older checkpoints.
Every newly accepted journal input advances its head and invalidates its checkpoint;
exact replay does neither. Reconciliation saves the complete head revision.
Historical suppression and current reads reject incomplete or mismatched heads.

`warmup.warmup_page(database, tenant, profile, cursor=None, limit=100)` compiles the
qualified catalog outside write locks and reconciles retained alerts in separate
atomic transactions under the coordinator, context, incident and alert locks.
It yields after 100 rows or 100 milliseconds between complete transactions and
returns scanned/completed counts, a continuation cursor and blocked alert codes.
The host preserves cursors and repeats sweeps. Missing creation baselines remain
blocked; current snapshots never substitute for retained historical proof.
Derived changes use the ordinary activity/projection/effect publisher without
inventing new source events or resetting inactivity.

`warmup_status(database, tenant)` reports one SQL snapshot of retained, missing
baseline, complete and pending counts. Neither function enables a capability.
A qualified activation procedure must lock all affected tenant coordinators and
verify current input heads/catalog generations atomically with the gate update;
a prior status response alone is not sufficient authorization to enable it.

Maintenance deletion verifies all external intent/final/cancel acknowledgments
through the common recovery adapter. Immediately before logical deletion it
rechecks the accepted actor's effective edit role under the identity guard and
coordinator and locks/checks maintenance and recovery capability gates. Lost
authorization cancels the prepared operation; a closed gate leaves it resumable.
Completed durable receipts remain idempotent.
