import asyncio
from datetime import UTC, datetime
from time import monotonic
from uuid import UUID, uuid4
from fastapi import FastAPI, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from appchi.ingestion.native import parse_json
from appchi.shared.errors import AppError, unavailable
from appchi.request_budget import request_budget


def create_http_app(lifespan, *, product=False):
    def validate_path(request: Request):
        if request.url.path.startswith("/api/"):
            route = request.scope.get("route")
            query_fields = getattr(getattr(route, "dependant", None), "query_params", ())
            allowed = {field.alias for field in query_fields}
            if set(request.query_params) - allowed:
                raise AppError("invalid_query", "Unknown query parameter.", 422)
            for field in query_fields:
                if (
                    field.field_info.annotation is bool
                    and field.alias in request.query_params
                    and request.query_params[field.alias] not in ("true", "false")
                ):
                    raise AppError(
                        "invalid_query", "Boolean query parameters require true or false.", 422
                    )
        for key, value in request.path_params.items():
            if key.endswith("_id"):
                try:
                    if str(UUID(value)) != value:
                        raise ValueError()
                except (ValueError, TypeError):
                    raise AppError("invalid_identifier", "Canonical UUID required.", 422) from None

    app = FastAPI(
        dependencies=[Depends(validate_path)],
        title="Appchi",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def error_response(request, error):
        content = {
            "code": error.code,
            "message": error.message,
            "request_id": getattr(request.state, "request_id", str(uuid4())),
        }
        if error.fields:
            content["fields"] = error.fields
        headers = {"Cache-Control": "private, no-store"}
        if error.status in (429, 503):
            delay = 10 if error.status == 429 else 5
            headers["Retry-After"] = str(delay)
            content["retry_after_seconds"] = delay
        return JSONResponse({"error": content}, error.status, headers=headers)

    @app.exception_handler(AppError)
    async def app_error(request, error):
        return error_response(request, error)

    if product:
        from appchi.cel import CELValidationError, CELUnavailableError

        @app.exception_handler(CELValidationError)
        async def cel_invalid(request, error):
            return error_response(
                request, AppError("invalid_cel", "CEL expression is invalid.", 422)
            )

        @app.exception_handler(CELUnavailableError)
        async def cel_unavailable(request, error):
            return error_response(request, unavailable("cel_unavailable"))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        return error_response(
            request,
            AppError(
                "invalid_fields",
                "Invalid request fields.",
                422,
                fields=[
                    {"path": ".".join(map(str, item["loc"])), "code": item["type"]}
                    for item in error.errors()
                ],
            ),
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request, error):
        return error_response(
            request, AppError("internal_error", "Unexpected application error.", 500)
        )

    if product:
        from psycopg import Error as DatabaseError
        from psycopg_pool import PoolTimeout

        @app.exception_handler(DatabaseError)
        @app.exception_handler(PoolTimeout)
        async def database_error(request, error):
            return error_response(request, unavailable("database_unavailable"))

    @app.middleware("http")
    async def protocol(request, call_next):
        request.state.request_id = str(uuid4())
        request.state.received_at = datetime.now(UTC)
        try:
            seconds = (
                5
                if "/ingest/" in request.url.path
                else 100
                if "/operators" in request.url.path and request.method != "GET"
                else 10
            )
            with request_budget(seconds):
                async with asyncio.timeout(seconds):
                    response = await handle(request, call_next)
        except TimeoutError:
            response = error_response(
                request,
                unavailable(
                    "ingress_timeout" if "/ingest/" in request.url.path else "request_timeout"
                ),
            )
        except AppError as error:
            response = error_response(request, error)
        response.headers.update(
            {
                "Cache-Control": (
                    "private, no-store, no-transform"
                    if response.headers.get("content-type", "").split(";")[0] == "text/event-stream"
                    else "private, no-store"
                ),
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Request-ID": request.state.request_id,
            }
        )
        return response

    async def handle(request, call_next):
        from appchi.workload import permits_http

        if not permits_http(request.app.state.settings, request.url.path):
            raise AppError("not_found", "Resource unavailable.", 404)
        if "/ingest/" in request.url.path or (
            request.method in ("POST", "PUT", "PATCH", "DELETE")
            and request.url.path.startswith("/api/")
        ):
            from appchi.clock_health import require_clock_health

            # A queued check may read evidence published after request arrival.
            # Validate freshness when the worker reads it; retain received_at for commands.
            await asyncio.to_thread(require_clock_health, request.app.state.settings)
        for key in request.query_params:
            if len(request.query_params.getlist(key)) > 1:
                raise AppError("duplicate_parameter", "Repeated query parameters are invalid.", 400)
        for key in (
            "idempotency-key",
            "x-receipt-token",
            "x-api-key",
            "authorization",
            "if-match",
            "origin",
            "x-csrf-token",
        ):
            if len(request.headers.getlist(key)) > 1:
                raise AppError("duplicate_header", "Repeated security headers are invalid.", 400)
        if request.method in ("POST", "PUT", "PATCH") and not request.url.path.startswith("/auth/"):
            if request.headers.get("content-encoding", "identity") != "identity":
                raise AppError(
                    "unsupported_encoding",
                    "Compressed request bodies are not accepted.",
                    415,
                )
            if request.headers.get("content-type", "").split(";")[0].lower() != "application/json":
                raise AppError("unsupported_media_type", "Use application/json.", 415)
            limit = (
                4 * 1024 * 1024
                if "/ingest/" in request.url.path
                else 512 * 1024
                if request.url.path.endswith("/alerts/counts")
                else 1024 * 1024
                if "/correlation-rules" in request.url.path
                else 256 * 1024
                if "/maintenance" in request.url.path
                else 65536
            )
            chunks = []
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise AppError("body_too_large", "Request body exceeds its size limit.", 413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
            request.state.receipt_started = monotonic()
            parse_json(request._body)
        return await call_next(request)

    @app.get("/livez", tags=["health"])
    def livez():
        return {"status": "alive"}

    @app.get("/readyz", tags=["health"])
    def readyz(request: Request):
        from appchi.probes import check_readiness

        configured = request.app.state.settings
        check_readiness(configured, request.app.state.db)
        return {"status": "ready", "scope": configured.role, "environment": configured.environment}

    return app
