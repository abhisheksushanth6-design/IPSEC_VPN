"""Application-level exception types and exception handlers.

Internal failure detail is logged server-side; clients receive a stable,
non-revealing error envelope.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class ApplicationError(Exception):
    """Base class for errors raised by this application."""

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    public_message = "An internal application error occurred."


class ConfigurationError(ApplicationError):
    """Raised when configuration is missing or invalid."""

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    public_message = "The application is not correctly configured."


class DatabaseInitializationError(ApplicationError):
    """Raised when the database cannot be created or reached."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    public_message = "The database is unavailable."


def _envelope(error: str, detail: object | None = None) -> dict[str, object]:
    payload: dict[str, object] = {"error": error}
    if detail is not None:
        payload["detail"] = detail
    return payload


def register_exception_handlers(app: FastAPI) -> None:
    """Attach the application's exception handlers to a FastAPI instance."""

    @app.exception_handler(ApplicationError)
    async def _application_error(
        _request: Request, exc: ApplicationError
    ) -> JSONResponse:
        logger.error("Application error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(exc.public_message),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Validation errors describe the client's own request, so the field
        # information is safe to return.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_envelope("Request validation failed", jsonable_encoder(exc.errors())),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def _unhandled_error(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception", exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_envelope("An unexpected server error occurred."),
        )
