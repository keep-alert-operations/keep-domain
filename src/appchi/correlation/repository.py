"""Correlation configuration authority and explicit future-consumer interfaces."""

from dataclasses import dataclass
from datetime import timedelta
import json
import time
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from appchi.cel import CELUnavailableError, CELValidationError, compile_expression
from appchi.cel.compiler import COST_MODEL, PROFILE
from appchi.ingestion.native import canonical
from appchi.shared.errors import AppError, unavailable
from appchi.serialization import wire
from .evidence import Boundary, Condition, EvidenceState, GroupKey, Rule, edit_rule, group_key
from .models import NAME_PROFILE, grouping, name_key

DEFINITION_FIELDS = ("name", "description", "severity", "window_minutes", "group_by", "conditions")
BUDGETS = (
    "enabled_rules_per_tenant",
    "live_groups_per_rule",
    "live_evidence_per_rule",
    "live_evidence_per_tenant",
    "condition_cost",
    "rule_cost",
    "tenant_cost",
    "digest_bucket",
)


def compile_conditions(definition, *, reuse=False):
    """Compile every condition; reuse=True shares this thread's warmed programs."""
    programs, cache = {}, {}
    deadline = time.monotonic() + 8
    for index, condition in enumerate(definition["conditions"]):
        if time.monotonic() >= deadline:
            raise unavailable("cel_compilation_deadline")
        source = condition["cel"]
        try:
            if source not in cache:
                cache[source] = compile_expression(source, rule=True, reuse=reuse)
                if "assignee_id" in cache[source].fields:
                    raise CELValidationError("Only approved alert fields may be referenced")
            programs[condition["id"]] = cache[source]
        except CELValidationError:
            raise AppError(
                "invalid_cel",
                "Correlation condition is invalid.",
                422,
                fields=[{"path": f"conditions.{index}.cel", "code": "invalid_rule_expression"}],
            ) from None
        except CELUnavailableError:
            raise unavailable("cel_compilation_unavailable") from None
    return programs


def limits(profile, *, allow_local_preview=False):
    config = (profile or {}).get("correlation", {})
    qualified = (profile or {}).get("qualified") is True
    local_preview = (
        allow_local_preview
        and (profile or {}).get("qualified") is False
        and (profile or {}).get("scope") == "local-development"
        and (profile or {}).get("correlation_preview") is True
    )
    if (
        not (qualified or local_preview)
        or config.get("cost_model") != COST_MODEL
        or any(type(config.get(key)) is not int or config[key] < 1 for key in BUDGETS)
    ):
        raise AppError(
            "correlation_capacity_profile_required",
            "Correlation rules require a qualified capacity profile or an enabled local preview.",
            503,
        )
    return config


def check_capacity(
    conn,
    tenant,
    definition,
    programs,
    profile,
    *,
    rule_id=None,
    enabled=True,
    allow_local_preview=False,
):
    config = limits(profile, allow_local_preview=allow_local_preview)
    costs = [programs[item["id"]].rule_cost_upper_bound for item in definition["conditions"]]
    if max(costs) > config["condition_cost"] or sum(costs) > config["rule_cost"]:
        raise AppError(
            "correlation_cost_exceeded", "Condition evaluation exceeds the capacity profile.", 422
        )
    if enabled:
        used = conn.execute(
            """SELECT count(*) AS rules,coalesce(sum(evaluation_cost),0) AS cost
            FROM correlation_rules WHERE tenant_id=%s AND enabled AND deleted_at IS NULL AND id<>%s""",
            (tenant, rule_id or uuid4()),
        ).fetchone()
        if (
            used["rules"] + 1 > config["enabled_rules_per_tenant"]
            or used["cost"] + sum(costs) > config["tenant_cost"]
        ):
            raise AppError(
                "correlation_capacity_exceeded", "Enabled rule capacity is exhausted.", 409
            )
    return sum(costs)


def get_rule(conn, tenant, rule, *, lock=False, include_deleted=False):
    row = conn.execute(
        "SELECT * FROM correlation_rules WHERE tenant_id=%s AND id=%s"
        + ("" if include_deleted else " AND deleted_at IS NULL")
        + (" FOR UPDATE" if lock else ""),
        (tenant, rule),
    ).fetchone()
    if not row:
        raise AppError("not_found", "Correlation rule unavailable.", 404)
    return _with_conditions(
        row,
        conn.execute(
            "SELECT * FROM correlation_conditions WHERE tenant_id=%s AND rule_id=%s ORDER BY position",
            (tenant, rule),
        ).fetchall(),
    )


def with_conditions(conn, tenant, rows):
    """Attach each rule's ordered conditions, as get_rule does, in one query."""
    items = {}
    if rows:
        for item in conn.execute(
            "SELECT * FROM correlation_conditions WHERE tenant_id=%s AND rule_id=ANY(%s::uuid[]) ORDER BY rule_id,position",
            (tenant, [row["id"] for row in rows]),
        ):
            items.setdefault(item["rule_id"], []).append(item)
    return tuple(_with_conditions(row, items.get(row["id"], [])) for row in rows)


def _with_conditions(row, items):
    row["condition_rows"] = items
    row["conditions"] = [
        {"id": str(item["id"]), "label": item["label"], "cel": item["cel"]} for item in items
    ]
    return row


def definition(row):
    return {key: row[key] for key in DEFINITION_FIELDS}


def public(row):
    return wire(
        {key: value for key, value in row.items() if key not in {"name_key", "condition_rows"}}
    )


@dataclass(frozen=True)
class _SourceOnly:
    source: str

    def evaluate(self, *_):
        raise RuntimeError("Configuration comparison cannot execute a condition")


def core_rule(row, programs):
    """Compile outside locks, then compare source/profile/revision under coordinator.

    The caller still owns event proof, evidence persistence, current alert checks,
    consumer cursor and incident ownership writes in a single transaction.
    """
    conditions = []
    for item in row["conditions"]:
        program = programs[item["id"]]
        if program.source != item["cel"] or getattr(program, "profile", PROFILE) != row["profile"]:
            raise AppError("revision_conflict", "Rule changed after compilation.", 409)
        conditions.append(Condition(UUID(item["id"]), item["label"], program))
    return Rule(
        UUID(str(row["id"])),
        UUID(str(row["tenant_id"])),
        row["created_at"],
        row["revision"],
        row["epoch"],
        row["grouping_generation"],
        Boundary(row["epoch_boundary_at"], row["epoch_boundary_order"]),
        tuple(conditions),
        grouping(row["group_by"]),
        row["window_minutes"],
        row["enabled"],
        row["deleted_at"] is not None,
        "healthy" if row["health"] == "healthy" else "blocked",
    )


def persist(conn, tenant, actor, now, body, programs, command_id, *, previous=None, enabled=None):
    """Caller holds authorization and tenant coordinator, then the current rule."""
    rule_id = previous["id"] if previous else uuid4()
    intent = previous["enabled"] if previous else True
    if enabled is not None:
        intent = enabled
    changed = [key for key in DEFINITION_FIELDS if previous is None or body[key] != previous[key]]
    if previous and intent != previous["enabled"]:
        changed.append("enabled")
    if not changed:
        return previous, False, None
    duplicate = conn.execute(
        "SELECT id FROM correlation_rules WHERE tenant_id=%s AND name_key=%s AND deleted_at IS NULL AND id<>%s",
        (tenant, name_key(body["name"]), rule_id),
    ).fetchone()
    if duplicate:
        raise AppError("name_unavailable", "Rule name is unavailable.", 409)
    # This branch uses the existing pure edit classifier. Source-only programs
    # are non-executable and exist only to compare the prior configuration.
    reset, generation_changed = previous is None, False
    if previous and previous.get("kafka_schema_blocked"):
        reset = True
        generation_changed = previous["group_by"] != body["group_by"]
    elif previous:
        old_programs = {item["id"]: _SourceOnly(item["cel"]) for item in previous["conditions"]}
        old = core_rule(previous, old_programs)
        new_conditions = tuple(
            Condition(UUID(item["id"]), item["label"], (programs or old_programs)[item["id"]])
            for item in body["conditions"]
        )
        edited = edit_rule(
            EvidenceState(old),
            Boundary(now, old.epoch_boundary.order),
            conditions=new_conditions,
            grouping=grouping(body["group_by"]),
            window_minutes=body["window_minutes"],
            enabled=intent,
        ).rule
        reset = edited.epoch != old.epoch
        generation_changed = edited.grouping_generation != old.grouping_generation
    revision = previous["revision"] + 1 if previous else 1
    epoch = previous["epoch"] + int(reset) if previous else 1
    generation = previous["grouping_generation"] + int(generation_changed) if previous else 1
    reason = (
        "created"
        if not previous
        else "grouping_changed"
        if generation_changed
        else "enabled"
        if intent and not previous["enabled"]
        else "disabled"
        if not intent and previous["enabled"]
        else "logic_changed"
        if reset
        else None
    )
    order = previous["epoch_boundary_order"] if previous else None
    if reset:
        progress = conn.execute(
            "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order,change_order",
            (tenant,),
        ).fetchone()
        order = progress["admission_order"]
    if not previous:
        conn.execute(
            "INSERT INTO correlation_rule_identities(id,tenant_id) VALUES(%s,%s)", (rule_id, tenant)
        )
    ready = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='correlation'"
    ).fetchone()["ready"]
    health = ("healthy" if ready else "blocked") if reset else previous["health"]
    blocked = (
        (None if ready else "consumer_not_integrated") if reset else previous["blocked_reason"]
    )
    cost = (
        sum(programs[item["id"]].rule_cost_upper_bound for item in body["conditions"])
        if programs
        else previous["evaluation_cost"]
    )
    conn.execute(
        """INSERT INTO correlation_rules(id,tenant_id,revision,epoch,grouping_generation,name,name_key,name_profile,
        description,severity,window_minutes,group_by,enabled,health,blocked_reason,last_reset_reason,profile,evaluation_cost,
        epoch_boundary_at,epoch_boundary_order,created_at,updated_at,created_by,updated_by)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,epoch=EXCLUDED.epoch,grouping_generation=EXCLUDED.grouping_generation,
        name=EXCLUDED.name,name_key=EXCLUDED.name_key,description=EXCLUDED.description,severity=EXCLUDED.severity,
        window_minutes=EXCLUDED.window_minutes,group_by=EXCLUDED.group_by,enabled=EXCLUDED.enabled,health=EXCLUDED.health,
        blocked_reason=EXCLUDED.blocked_reason,last_reset_reason=EXCLUDED.last_reset_reason,profile=EXCLUDED.profile,
        evaluation_cost=EXCLUDED.evaluation_cost,epoch_boundary_at=EXCLUDED.epoch_boundary_at,epoch_boundary_order=EXCLUDED.epoch_boundary_order,
        updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by""",
        (
            rule_id,
            tenant,
            revision,
            epoch,
            generation,
            body["name"],
            name_key(body["name"]),
            NAME_PROFILE,
            body["description"],
            body["severity"],
            body["window_minutes"],
            Jsonb(body["group_by"]),
            intent,
            health,
            blocked,
            reason or previous["last_reset_reason"],
            PROFILE,
            cost,
            now if reset else previous["epoch_boundary_at"],
            order,
            previous["created_at"] if previous else now,
            now,
            previous["created_by"] if previous else actor["id"],
            actor["id"],
        ),
    )
    if reset:
        conn.execute(
            "UPDATE correlation_rules SET kafka_schema_blocked=false WHERE tenant_id=%s AND id=%s",
            (tenant, rule_id),
        )
    stored = {str(item["id"]): item for item in previous["condition_rows"]} if previous else {}
    conn.execute(
        "DELETE FROM correlation_conditions WHERE tenant_id=%s AND rule_id=%s", (tenant, rule_id)
    )
    for position, item in enumerate(body["conditions"]):
        conn.execute(
            "INSERT INTO correlation_condition_identities(id,tenant_id,rule_id) VALUES(%s,%s,%s) ON CONFLICT(id) DO NOTHING",
            (item["id"], tenant, rule_id),
        )
        identity = conn.execute(
            "SELECT rule_id FROM correlation_condition_identities WHERE tenant_id=%s AND id=%s",
            (tenant, item["id"]),
        ).fetchone()
        if not identity or identity["rule_id"] != rule_id:
            raise AppError(
                "condition_identity_unavailable", "Condition ID is unavailable for this rule.", 409
            )
        program = programs.get(item["id"]) if programs else None
        conn.execute(
            """INSERT INTO correlation_conditions(tenant_id,rule_id,id,position,label,label_key,cel,profile,checked_program,evaluation_cost)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                tenant,
                rule_id,
                item["id"],
                position,
                item["label"],
                name_key(item["label"]),
                item["cel"],
                PROFILE,
                program.checked if program else stored[item["id"]]["checked_program"],
                program.rule_cost_upper_bound if program else stored[item["id"]]["evaluation_cost"],
            ),
        )
    if reset:
        conn.execute(
            """INSERT INTO correlation_rule_controls(id,tenant_id,rule_id,revision,epoch,grouping_generation,effective_at,tenant_order,observed_change_order,kind)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                uuid4(),
                tenant,
                rule_id,
                revision,
                epoch,
                generation,
                now,
                order,
                progress["change_order"],
                reason,
            ),
        )
        # Older epoch evidence remains stored for dependency-aware cleanup but is
        # immediately unusable. Never scan current alerts to repopulate it.
    # The first configured rule starts at current canonical progress; previously
    # accepted inputs are not a historical backfill. Existing consumers retain
    # their own checkpoint so configuring another rule never skips pending work.
    current_order = conn.execute(
        "SELECT change_order FROM tenant_work_state WHERE tenant_id=%s", (tenant,)
    ).fetchone()["change_order"]
    conn.execute(
        "INSERT INTO correlation_consumer_state(tenant_id,change_order,pending) VALUES(%s,%s,true) ON CONFLICT(tenant_id) DO UPDATE SET pending=true,updated_at=clock_timestamp()",
        (tenant, current_order),
    )
    row = get_rule(conn, tenant, rule_id)
    conn.execute(
        """INSERT INTO correlation_rule_revisions(tenant_id,rule_id,revision,snapshot,action,reset_reason,changed_fields,command_id,recorded_at,actor_id,actor_label)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            tenant,
            rule_id,
            revision,
            Jsonb(public(row)),
            "created" if previous is None else "updated",
            reason,
            Jsonb(changed),
            command_id,
            now,
            actor["id"],
            actor["display_name"],
        ),
    )
    view = conn.execute(
        "UPDATE tenant_view_state SET resource_generation=resource_generation+1,view_generation=view_generation+1 WHERE tenant_id=%s RETURNING resource_generation",
        (tenant,),
    ).fetchone()
    conn.execute(
        "INSERT INTO application_outbox(id,tenant_id,stream,stream_order,envelope) VALUES(%s,%s,%s,%s,%s)",
        (
            uuid4(),
            tenant,
            "resource:correlation:" + str(rule_id),
            revision,
            canonical(
                wire(
                    {
                        "version": 1,
                        "tenant_id": tenant,
                        "resource_kind": "correlation",
                        "resource_id": rule_id,
                        "revision": revision,
                        "resource_generation": view["resource_generation"],
                    }
                )
            ),
        ),
    )
    return row, True, reason


def ensure_context(conn, row, key: GroupKey, *, max_bucket: int):
    """Caller holds tenant coordinator and rule lock; digest collisions are safe."""
    if type(max_bucket) is not int or max_bucket < 1:
        raise unavailable("correlation_capacity_profile_required")
    try:
        values = json.loads(key.canonical)
        fields = grouping(row["group_by"])
        if len(values) != len(fields) or any(
            item[:2] != [field.name, field.kind] for item, field in zip(values, fields)
        ):
            raise ValueError()
        reconstructed = group_key(fields, {item[0]: item[2] for item in values})
        if reconstructed is None or reconstructed.canonical != key.canonical:
            raise ValueError()
    except (ValueError, TypeError, IndexError):
        raise AppError("invalid_group_key", "Invalid typed group identity.", 422) from None
    candidates = conn.execute(
        """SELECT id,group_key FROM correlation_contexts WHERE tenant_id=%s AND rule_id=%s
        AND grouping_generation=%s AND group_digest=%s ORDER BY id LIMIT %s FOR UPDATE""",
        (row["tenant_id"], row["id"], row["grouping_generation"], key.digest, max_bucket + 1),
    ).fetchall()
    for candidate in candidates:
        if bytes(candidate["group_key"]) == key.canonical:
            return candidate["id"]
    if len(candidates) >= max_bucket:
        raise unavailable("correlation_digest_bucket_capacity")
    context = uuid4()
    conn.execute(
        "INSERT INTO correlation_contexts(id,tenant_id,rule_id,grouping_generation,group_digest,group_key,created_at) VALUES(%s,%s,%s,%s,%s,%s,clock_timestamp())",
        (
            context,
            row["tenant_id"],
            row["id"],
            row["grouping_generation"],
            key.digest,
            key.canonical,
        ),
    )
    return context


def retained_revisions(conn, row, now):
    """SQL fragment parameters keep concrete dependency holds beyond 90 days."""
    query = """WITH versions AS (
      SELECT r.*,lead(recorded_at) OVER(ORDER BY revision) AS superseded_at
      FROM correlation_rule_revisions r WHERE tenant_id=%s AND rule_id=%s)
      SELECT * FROM versions v WHERE
      (superseded_at IS NOT NULL AND superseded_at+interval '2160 hours'>%s)
      OR (revision=%s AND (%s::timestamptz IS NULL OR %s::timestamptz+interval '2160 hours'>%s))
      OR EXISTS(SELECT 1 FROM correlation_revision_holds h WHERE h.tenant_id=v.tenant_id AND h.rule_id=v.rule_id
                AND h.revision=v.revision AND h.released_at IS NULL)"""
    return query, [
        row["tenant_id"],
        row["id"],
        now,
        row["revision"],
        row["deleted_at"],
        row["deleted_at"],
        now,
    ]


def history_public(row, now):
    activity = row["recorded_at"] + timedelta(days=90) > now
    return wire(
        {
            "revision": row["revision"],
            "recorded_at": row["recorded_at"],
            "definition": row["snapshot"],
            "activity": {
                key: row[key]
                for key in (
                    "action",
                    "reset_reason",
                    "changed_fields",
                    "command_id",
                    "actor_id",
                    "actor_label",
                )
            }
            if activity
            else None,
        }
    )
