"""
RedGNAT FastAPI application factory.

Start with:
    uvicorn redgnat.api.app:create_app --factory --host 0.0.0.0 --port 8000

Or via Makefile:
    make api
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_API_KEY_HEADER = "X-API-Key"


def create_app() -> "Any":
    try:
        from fastapi import Depends, FastAPI, HTTPException, Security, status
        from fastapi.security.api_key import APIKeyHeader
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError as exc:
        raise RuntimeError("FastAPI not installed — pip install fastapi uvicorn[standard]") from exc

    app = FastAPI(
        title="RedGNAT CART API",
        description="Continuous Automated Red Teaming management interface",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # Explicitly configured origins only — default to none (same-origin).
    # Set REDGNAT_CORS_ORIGINS=https://dash.example.com to enable a UI origin.
    _cors_origins = [
        o.strip()
        for o in os.environ.get("REDGNAT_CORS_ORIGINS", "").split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=[_API_KEY_HEADER, "Content-Type"],
    )

    # ------------------------------------------------------------------
    # API key authentication
    # ------------------------------------------------------------------
    api_key_scheme = APIKeyHeader(name=_API_KEY_HEADER, auto_error=True)
    _expected_key = os.environ.get("REDGNAT_API_KEY", "")

    async def verify_api_key(api_key: str = Security(api_key_scheme)) -> str:
        if _expected_key and api_key != _expected_key:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key"
            )
        return api_key

    # ------------------------------------------------------------------
    # Health check (no auth)
    # ------------------------------------------------------------------
    @app.get("/api/v1/health", tags=["meta"])
    async def health() -> dict:
        return {"status": "ok", "service": "redgnat"}

    # ------------------------------------------------------------------
    # Include routers
    # ------------------------------------------------------------------
    from redgnat.api.routes.scenarios import router as scenarios_router
    from redgnat.api.routes.runs import router as runs_router
    from redgnat.api.routes.intel import router as intel_router
    from redgnat.api.routes.stix import router as stix_router

    app.include_router(scenarios_router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
    app.include_router(runs_router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
    app.include_router(intel_router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
    app.include_router(stix_router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])

    return app
