"""Explicit deployment activation after qualified capacity and atomic proof checks."""

from hashlib import sha256
import json

from psycopg.types.json import Jsonb

from appchi.maintenance.runtime import prepare_qualified_catalog
from appchi.maintenance.warmup import proof_counts
from appchi.shared.errors import AppError, unavailable


def activate(db, profile, operation_reference):
    if (
        not isinstance(profile, dict)
        or profile.get("qualified") is not True
        or any(
            not isinstance(profile.get(key), str) or not 1 <= len(profile[key]) <= 256
            for key in ("id", "qualification_evidence")
        )
        or not isinstance(operation_reference, str)
        or not 1 <= len(operation_reference) <= 256
    ):
        raise unavailable("maintenance_qualification_required")
    digest = sha256(
        json.dumps(profile, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    reason = "qualified:" + digest
    with db.transaction() as conn:
        tenants = [row["id"] for row in conn.execute("SELECT id FROM tenants ORDER BY id")]
    # All compilation and native work finishes outside the activation locks.
    catalogs = {tenant: prepare_qualified_catalog(db, tenant, profile) for tenant in tenants}
    with db.transaction() as conn:
        # Prevent an uninspected tenant from appearing while closing the proof set.
        conn.execute("LOCK TABLE tenants IN SHARE MODE")
        current = [row["id"] for row in conn.execute("SELECT id FROM tenants ORDER BY id")]
        if current != tenants:
            raise unavailable("maintenance_activation_tenants_changed")
        states = conn.execute(
            "SELECT * FROM tenant_work_state ORDER BY tenant_id FOR UPDATE"
        ).fetchall()
        if {row["tenant_id"] for row in states} != set(tenants):
            raise unavailable("maintenance_activation_order_missing")
        gate = conn.execute(
            "SELECT * FROM capability_gates WHERE capability='maintenance' FOR UPDATE"
        ).fetchone()
        if not gate:
            raise unavailable("maintenance_capability_missing")
        if gate["ready"]:
            if gate["reason"] != reason:
                raise AppError(
                    "maintenance_profile_conflict", "Active capacity binding differs.", 409
                )
            return {"state": "already_active", "profile_digest": digest}
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        for state in states:
            if state["blocked"] or (state["last_clock"] and now < state["last_clock"]):
                raise unavailable("maintenance_activation_order_untrusted")
            tenant = state["tenant_id"]
            view = conn.execute(
                "SELECT maintenance_generation FROM tenant_view_state WHERE tenant_id=%s", (tenant,)
            ).fetchone()
            if not view or view["maintenance_generation"] != catalogs[tenant].generation:
                raise unavailable("maintenance_activation_catalog_changed")
            counts = proof_counts(conn, tenant)
            if (
                counts["missing_baseline"]
                or counts["pending"]
                or counts["complete"] != counts["retained"]
            ):
                raise unavailable("maintenance_activation_proof_incomplete")
        conn.execute(
            "UPDATE capability_gates SET ready=true,reason=%s WHERE capability='maintenance'",
            (reason,),
        )
        conn.execute(
            """INSERT INTO audit_events(tenant_id,actor_id,actor_label,kind,evidence)
            VALUES(NULL,NULL,'configuration-loader','maintenance-capability-activated',%s)""",
            (
                Jsonb(
                    {
                        "operation_reference": operation_reference,
                        "profile_id": profile["id"],
                        "qualification_evidence": profile["qualification_evidence"],
                        "profile_digest": digest,
                        "tenant_count": str(len(tenants)),
                    }
                ),
            ),
        )
        return {"state": "active", "profile_digest": digest, "tenant_count": str(len(tenants))}


def main():
    import argparse
    from appchi.config import Settings
    from appchi.db import Database

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-reference", required=True)
    args = parser.parse_args()
    db = None
    try:
        settings = Settings()
        if not settings.capacity_profile:
            raise unavailable("maintenance_qualification_required")
        with settings.capacity_profile.open("rb") as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise unavailable("maintenance_qualification_required")
        profile = json.loads(raw)
        db = Database(
            settings.database_url.get_secret_value(),
            settings.pool_size,
            deployment_epoch=settings.deployment_epoch,
        )
        print(json.dumps(activate(db, profile, args.operation_reference)))
    except Exception as error:
        print(
            json.dumps(
                {
                    "error": error.code
                    if isinstance(error, AppError)
                    else "maintenance_activation_failed"
                }
            )
        )
        raise SystemExit(1) from None
    finally:
        if db:
            db.close()


if __name__ == "__main__":
    main()
