"""Intel feed routes — GET /intel/feeds, POST /intel/ingest."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException

router = APIRouter(tags=["intel"])


def _get_client() -> Any:
    from redgnat.client import RedGNATClient
    return RedGNATClient()


@router.post("/intel/ingest")
async def trigger_ingest() -> dict:
    """Manually trigger intel ingestion from GNAT and SandGNAT."""
    client = _get_client()
    feeds = client.ingest_latest()
    return {"feeds_ingested": len(feeds), "feed_ids": [f.feed_id for f in feeds]}


@router.post("/intel/probe-request")
async def submit_probe_request(body: dict = Body(...)) -> dict:
    """
    Accept a ProbeRequest from GNAT AI agents and enqueue it as a Celery task.

    This is the inbound half of the bidirectional feedback loop: GNAT's LLM
    agents analyse gap notes pulled from GET /stix/gaps and POST new probe
    instructions back here to drive follow-on emulation runs.

    Expected body: ProbeRequest.to_dict() output.
    """
    from redgnat.emulation.tasks import run_probe_task

    if not body.get("technique_id"):
        raise HTTPException(status_code=422, detail="technique_id is required")

    task = run_probe_task.delay(body)
    return {"queued": True, "task_id": task.id, "technique_id": body["technique_id"]}


@router.get("/intel/techniques")
async def list_registered_techniques() -> list[dict]:
    """List all registered ATT&CK technique IDs and their metadata."""
    from redgnat.techniques.registry import list_technique_ids
    from redgnat.scenarios.ttp_mapper import TTPMapper

    mapper = TTPMapper()
    result = []
    for tid in list_technique_ids():
        info = mapper.get(tid)
        result.append({
            "technique_id": tid,
            "name": info.name if info else tid,
            "tactic": info.tactic if info else "unknown",
            "description": info.description if info else "",
        })
    return result
