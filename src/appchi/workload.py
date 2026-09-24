"""Application route boundaries supplement the deployment network policies."""

HTTP_ROLES = frozenset({"product-api", "ingestion-api", "private-ingestion"})


def permits_http(settings, path):
    if path in ("/livez", "/readyz"):
        return settings.role in HTTP_ROLES
    # One isolated development process can exercise the whole application.
    # Deployed workload roles have their own route surface in every other environment.
    if settings.environment == "development" and settings.role == "product-api":
        return True
    if settings.role == "product-api":
        return path.startswith(("/auth/", "/api/tenants", "/api/admin/"))
    if settings.role == "ingestion-api":
        return path.startswith("/api/ingest/v1/")
    if settings.role == "private-ingestion":
        return path.startswith("/api/ingest/v2/")
    return False
