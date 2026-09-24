"""Public capability readiness and a credential-free-output private-listener probe."""

from appchi.shared.errors import unavailable


def check_readiness(settings, db):
    required = {
        "product-api": ("human_auth",),
        "private-ingestion": ("v2_ingress",),
        "indexer": ("search",),
        "source": (),
        "ingestion-api": (),
    }
    if settings.role not in required:
        raise unavailable("workload_role_unconfigured")
    with db.transaction() as conn:
        conn.execute("SELECT 1")
        for capability in required[settings.role]:
            row = conn.execute(
                "SELECT ready FROM capability_gates WHERE capability=%s", (capability,)
            ).fetchone()
            if not row or not row["ready"]:
                raise unavailable("workload_capability_unready")
    if settings.role in ("ingestion-api", "private-ingestion"):
        import json

        profile = (
            json.loads(settings.capacity_profile.read_text(encoding="utf-8"))
            if settings.capacity_profile
            else None
        )
        if not profile or (settings.environment != "development" and not profile.get("qualified")):
            raise unavailable("capacity_profile_required")


def main():
    import argparse
    from appchi.config import Settings
    from appchi.db import Database

    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("product-api", "ingestion-api", "private-ingestion"))
    args = parser.parse_args()
    database = None
    try:
        settings = Settings(role=args.role)
        database = Database(
            settings.database_url.get_secret_value(), 1, deployment_epoch=settings.deployment_epoch
        )
        check_readiness(settings, database)
    except Exception:
        raise SystemExit(1) from None
    finally:
        if database:
            database.close()


if __name__ == "__main__":
    main()
