"""FastAPI application entry point.

AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework.

SECTION 0 — project foundation. No security analysis is performed here.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.api.routes.packets import register_packet_error_handler
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging_config import configure_logging
from app.db.init_db import initialize_database
from app.websocket.routes import router as websocket_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialise the database on startup and log a clean shutdown."""
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("Starting %s (mode=%s)", settings.project_name, settings.application_mode)
    initialize_database()
    logger.info("Database initialised")
    yield
    logger.info("Shutdown complete")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.project_name,
        description=(
            "Foundation API for the AI-Powered IPsec VPN Protocol Analyzer and "
            "Security Assessment Framework. Security analysis layers are not "
            "implemented."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    register_packet_error_handler(app)
    app.include_router(api_router, prefix=settings.api_prefix)
    app.include_router(websocket_router)

    # Mount frontend static distribution when built
    from pathlib import Path
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    dist_dir = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        if (dist_dir / "assets").exists():
            app.mount("/assets", StaticFiles(directory=dist_dir / "assets"), name="static_assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str):
            if full_path.startswith("api") or full_path.startswith("ws"):
                from starlette.exceptions import HTTPException
                raise HTTPException(status_code=404, detail="Not Found")
            target = dist_dir / full_path
            if full_path and target.is_file():
                return FileResponse(target)
            return FileResponse(dist_dir / "index.html")

    return app


app = create_app()
