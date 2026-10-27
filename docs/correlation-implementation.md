# Correlation implementation

PostgreSQL owns rule configuration, immutable revisions and condition identities,
evaluation epochs, complete typed context keys, evidence, consumer progress and
automatic ownership decisions. CEL uses the selected native checked runtime.
Elasticsearch and Kafka do not establish correlation eligibility.

## API

The prefix is `/api/tenants/{tenant_id}/correlation-rules`:

- `GET /` lists rules in creation-time/UUID arbitration order, with optional name,
  enabled, health, state and name-sort filters. Pages default to 50 and cap at 200.
- `POST /`, `PUT /{rule_id}`, and `POST /{rule_id}/enable` or `/disable` use command
  UUIDs and canonical expected revision strings. Mutations reauthorize retries.
- `GET /{rule_id}`, `/history`, `/history/{revision}`, and `/diagnostics` read
  current authorized PostgreSQL state. Cursor payloads are encrypted and bind
  tenant, session, deployment, filters and a fixed fifteen-minute expiry.
- `POST /validate` validates an unsaved definition and reports conservative cost.
  `POST /test` evaluates an unsaved definition against one selected retained alert.
  Testing creates no evidence or automatic action and reports that distinction.
- `DELETE /{rule_id}` takes `Idempotency-Key` and a quoted `If-Match` revision.
  It requires the recovery capability and a configured independent evidence store.
  `GET /deletions/{job_id}` exposes safe operation progress.

Rule definitions contain `name`, `description`, `severity`, `conditions` with
stable UUID/label/CEL fields, ordered `group_by` fields, and `window_minutes`.
Metadata edits preserve the evaluation epoch. Condition logic/identity, window,
grouping or enabled-intent changes establish a new arrival boundary and epoch;
grouping changes also advance the grouping generation. Creation time never changes.
An empty grouping list is a typed singleton group. Context digest buckets always
compare complete canonical bytes; a hash match alone is not identity.

Superseded definitions remain readable for ninety days from supersession, current
definitions indefinitely, and a deleted final definition for ninety days from
deletion. Concrete dependency holds can extend a needed revision. Actor/command
activity is independently limited to ninety days. Retention reads use elapsed
UTC durations. This module does not implement physical configuration compaction.

## Consumer and incident integration

`correlation.runtime.worker_turn(database, tenant, profile)` compiles definitions
before acquiring the tenant coordinator. It rechecks the exact configured rule
revisions, takes rule/context/incident/alert locks, and applies one ordered input
to every applicable rule before selecting one complete winning action. Journal
rows and maintenance derived effects share the canonical tenant change order.

The same transaction commits evidence, cursor and pending work, incident state,
links, exclusive active ownership, provenance and projection/outbox publication.
It can attach more than the manual 100-alert selection limit. A failure rolls
back the entire action. Each later turn recomputes from current state; accepted
pending source work prevents automatic action on affected alerts. Final selection
uses PostgreSQL time sampled after decision locks. Expiry is exclusive.

Maintenance corrections replay only the affected alert from retained original
field transitions, current complete cause intervals and active unsuppression
qualifiers. Replay verifies the whole field chain against the authoritative
current snapshot before assigning its observed revision. Original timestamps,
scheduled boundaries and reset/release fences are preserved. No artificial
historical semantic revisions are introduced. Later queued canonical entries
keep the affected alert ineligible until its current proof is processed.
Missing proof or exhausted replay bounds stops progress visibly; rows are never
silently truncated into an apparently complete decision.

Manual unlink and Move establish release barriers and clear affected evidence.
Resolution clears only the exact originating context, including an old grouping
generation. Reopen atomically reclaims the full original context and alert owners
or fails; it creates no historical evidence. Incident inactivity uses the same
context reset. Deleted or disabled origins remain manually manageable.

## Protected deletion

`correlation.deletion.resume_delete` resumes durable `prepared`, `deleted`,
`final_protected` or `cancelled` jobs. Every remote phase uses a stable evidence
UUID and the shared strict durable-acknowledgement validator. Remote calls happen
outside database locks. After intent acknowledgement, the commit rechecks current
authorization, recovery capability and expected revision under the coordinator.
Retirement increments revision/epoch, disables the rule, clears its evidence,
releases its name and preserves incident context identity. Success receipts are
written only after final acknowledgement. Cancelled attempts block a replacement
attempt until their cancellation is durably protected. No rule content enters
the independent minimal evidence record.

## Capacity and verification

Correlation is always on (REV-39, 2026-10-24): no capability gate, activation
or `qualified` flag is required, rules are created `healthy`, and the API no
longer returns `processing_ready`. The `correlation` keys `enabled_rules_per_tenant`,
`live_groups_per_rule`, `live_evidence_per_rule`, `live_evidence_per_tenant`,
`condition_cost`, `rule_cost`, `tenant_cost` and `digest_bucket` are optional and
read through `appchi.shared.capacity`: a missing or null key is unlimited, and a
value other than an integer from 1 to `UNLIMITED` (2^53-1) fails with
`capacity_profile_invalid`. An optional `cost_model` must equal the CEL cost model
(`correlation_cost_model_mismatch`). Maintenance work/input/segment bounds follow
the same rule. Test allocations exercise enforcement and are not production
capacity measurements.

Local verification covers actual PostgreSQL authorization and RLS, native CEL,
configuration reset/idempotency, complete typed hash-collision comparison,
concurrent consumers, rollback after incident writes, original-time maintenance
replay, ownership/reopen/release boundaries and complete attachment sets above
100. Independent-store failure tests use controlled acknowledgements to exercise
the application protocol; they do not qualify an external evidence service.
