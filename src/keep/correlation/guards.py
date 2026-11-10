from keep.shared.errors import unavailable


def _ready(conn):
    gate = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='recovery' FOR SHARE"
    ).fetchone()
    if not gate or not gate["ready"]:
        raise unavailable("recovery_not_ready")
