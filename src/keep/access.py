from keep.observability import http as observe
from keep.shared.errors import AppError

ROLE_RANK = {"view": 1, "edit": 2, "admin": 3}


def effective_role(conn, principal, tenant):
    row = conn.execute("SELECT kind FROM tenants WHERE id=%s", (tenant,)).fetchone()
    if not row or not principal["eligible"] or principal.get("deleted"):
        return None
    if principal["super_admin"]:
        return "admin"
    if row["kind"] == "global":
        return "edit"
    roles = conn.execute(
        "SELECT g.role FROM tenant_grants g WHERE g.tenant_id=%s AND (g.principal_id=%s OR g.principal_id IN (SELECT team_id FROM directory_memberships WHERE user_id=%s))",
        (tenant, principal["id"], principal["id"]),
    ).fetchall()
    return max((row["role"] for row in roles), key=ROLE_RANK.get, default=None)


def accessible_tenants(conn, principal):
    # Resolve inherited/direct grants and highest-role precedence in one query.
    if not principal["eligible"] or principal.get("deleted"):
        return []
    return conn.execute(
        """WITH roles AS (
            SELECT tenant_id, max(CASE role WHEN 'admin' THEN 3
                WHEN 'edit' THEN 2 ELSE 1 END) AS rank
            FROM tenant_grants
            WHERE principal_id=%s OR principal_id IN (
                SELECT team_id FROM directory_memberships WHERE user_id=%s)
            GROUP BY tenant_id
        )
        SELECT t.*, CASE WHEN %s THEN 'admin' WHEN t.kind='global' THEN 'edit'
            WHEN r.rank=3 THEN 'admin' WHEN r.rank=2 THEN 'edit' ELSE 'view' END AS role
        FROM tenants t LEFT JOIN roles r ON r.tenant_id=t.id
        WHERE %s OR t.kind='global' OR r.rank IS NOT NULL
        ORDER BY (t.kind='global') DESC,t.name_key,t.id""",
        (principal["id"], principal["id"], principal["super_admin"], principal["super_admin"]),
    ).fetchall()


def authorize(conn, request, tenant, minimum="view", mutation=False):
    from keep.identity.authentication import authenticate

    principal, session = authenticate(conn, request, mutation=mutation)
    observe.actor(request, principal["id"], tenant)
    role = effective_role(conn, principal, tenant)
    if role is None:
        raise AppError("not_found", "Resource unavailable.", 404)
    if ROLE_RANK[role] < ROLE_RANK[minimum]:
        raise AppError("forbidden", "This action requires additional permission.", 403)
    conn.execute("SELECT set_config('keep.tenant_id',%s,true)", (str(tenant),))
    return principal, session, role


def assignee(conn, tenant, principal_id):
    if principal_id is None:
        return
    principal = conn.execute(
        "SELECT * FROM principals WHERE id=%s AND kind='user'", (principal_id,)
    ).fetchone()
    if not principal or ROLE_RANK.get(effective_role(conn, principal, tenant), 0) < 2:
        raise AppError("ineligible_assignee", "Choose a user with current edit access.")
