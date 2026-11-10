from keep.shared.errors import unavailable


def _ready(conn, capability="recovery"):
    row = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability=%s FOR SHARE", (capability,)
    ).fetchone()
    if not row or not row["ready"]:
        raise unavailable(capability + "_not_ready")


def _guard(conn, tenant):
    conn.execute(
        "SELECT tenant_id FROM tenant_configuration_guard WHERE tenant_id=%s FOR UPDATE", (tenant,)
    )
