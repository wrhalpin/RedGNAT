"""Intel feed routes — GET /intel/feeds, POST /intel/ingest."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter

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
