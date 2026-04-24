# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Run query routes — GET /runs, GET /runs/{run_id}, POST /runs/{run_id}/investigation."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query

logger = logging.getLogger(__name__)
router = APIRouter(tags=["runs"])


def _get_client() -> Any:
    from redgnat.client import RedGNATClient
    return RedGNATClient()


@router.get("/runs")
async def list_runs(
    scenario_id: str | None = Query(None),
    investigation_id: str | None = Query(None),
) -> list[dict]:
    """
    List emulation runs, optionally filtered by scenario_id or investigation_id.

    Both filters can be combined (AND semantics).
    """
    client = _get_client()
    store = client._get_store()
    return [
        r.to_dict()
        for r in store.list_runs(scenario_id=scenario_id, investigation_id=investigation_id)
    ]


@router.get("/runs/{run_id}")
async def get_run(run_id: str) -> dict:
    """Return a single EmulationRun by ID, including investigation context fields."""
    client = _get_client()
    run = client.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    return run.to_dict()


@router.get("/runs/{run_id}/results")
async def get_run_results(run_id: str) -> list[dict]:
    """Return all TechniqueResults for a run."""
    client = _get_client()
    store = client._get_store()
    results = store.list_results(run_id)
    return [r.to_dict() for r in results]


@router.get("/runs/{run_id}/report")
async def get_run_report(run_id: str) -> dict:
    """Return a full CART report dict for a completed run."""
    from redgnat.reports.cart_report import CARTReport

    client = _get_client()
    store = client._get_store()

    run = client.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    scenario = client.get_scenario(run.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Parent scenario not found")

    results = store.list_results(run_id)
    report = CARTReport(scenario, run, results)
    return report.full_report_dict()


@router.post("/runs/{run_id}/investigation")
async def tag_run_with_investigation(
    run_id: str,
    body: dict = Body(...),
) -> dict:
    """
    Post-hoc tagging — associate a completed run with a GNAT investigation.

    Body fields:

        investigation_id  (required) — GNAT investigation ID.
        hypothesis_id     (optional) — GNAT Hypothesis ID.
        tenant_id         (optional) — GNAT tenant for multi-tenant setups.
        link_type         (optional) — "inferred" (default for post-hoc tagging).

    The stored STIX bundle is not retroactively mutated. GNAT can re-pull updated
    objects from the STIX endpoints once this tag is applied.
    """
    client = _get_client()
    store = client._get_store()

    run = client.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    investigation_id: str = body.get("investigation_id", "")
    if not investigation_id:
        raise HTTPException(status_code=400, detail="investigation_id is required")

    run.investigation_id = investigation_id
    run.hypothesis_id = body.get("hypothesis_id") or run.hypothesis_id
    run.investigation_tenant_id = body.get("tenant_id") or run.investigation_tenant_id
    store.upsert_run(run)

    logger.info(
        "tag_run_with_investigation: run %s tagged with investigation=%s hypothesis=%s (inferred)",
        run_id,
        investigation_id,
        run.hypothesis_id,
    )
    return run.to_dict()
