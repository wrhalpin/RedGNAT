# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""STIX export routes — consumed by the GNAT RedGNATConnector plugin."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["stix"])


def _get_client() -> Any:
    from redgnat.client import RedGNATClient
    return RedGNATClient()


@router.get("/stix/results")
async def list_stix_results() -> list[dict]:
    """
    Return all emulation run results as STIX 2.1 CourseOfAction objects.

    Investigation-scoped runs are also stamped with x_gnat_investigation_*
    properties. Consumed by the GNAT RedGNATConnector plugin.
    """
    client = _get_client()
    store = client._get_store()
    runs = client.list_runs()
    coa_objects = []
    for run in runs:
        scenario = client.get_scenario(run.scenario_id)
        if not scenario:
            continue
        results = store.list_results(run.run_id)
        coa_objects.append(_run_to_stix_coa(run, scenario, results))
    return coa_objects


@router.get("/stix/results/{run_id}")
async def get_stix_result(run_id: str) -> dict:
    client = _get_client()
    run = client.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    scenario = client.get_scenario(run.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Parent scenario not found")
    store = client._get_store()
    results = store.list_results(run_id)
    return _run_to_stix_coa(run, scenario, results)


@router.get("/stix/sightings")
async def list_stix_sightings() -> list[dict]:
    """
    Return all TechniqueResults as STIX 2.1 Sighting objects.

    Sightings from investigation-scoped runs are stamped with investigation context.
    """
    client = _get_client()
    store = client._get_store()
    sightings = []
    for run in client.list_runs():
        for result in store.list_results(run.run_id):
            sighting = result.to_stix_sighting()
            if run.investigation_id:
                _stamp(sighting, run)
            sightings.append(sighting)
    return sightings


@router.get("/stix/gaps")
async def list_stix_gaps() -> list[dict]:
    """
    Return gap reports as STIX 2.1 Note objects.

    Consumed by the GNAT RedGNATConnector (list_objects("note")) so GNAT
    operators and AI agents can see which techniques went undetected and
    what intel collection GNAT should task.
    """
    client = _get_client()
    store = client._get_store()
    from redgnat.feedback.gap_reporter import GapReporter

    reporter = GapReporter(client.config)
    notes = []
    for run in client.list_runs():
        results = store.list_results(run.run_id)
        report = reporter.build_report(
            run.run_id,
            run.scenario_id,
            results,
            investigation_id=run.investigation_id,
            hypothesis_id=run.hypothesis_id,
        )
        if report.gaps:
            notes.append(report.to_stix_note())
    return notes


@router.get("/stix/groupings")
async def list_stix_groupings() -> list[dict]:
    """
    Return STIX 2.1 Grouping objects for all investigation-scoped runs.

    Each Grouping envelopes the CoA, Sightings, and gap Note emitted by one run.
    Consumed by GNAT via the RedGNATConnector (list_objects("grouping")).
    """
    from redgnat.feedback.gap_reporter import GapReporter
    from redgnat.feedback.investigation_context import build_grouping

    client = _get_client()
    store = client._get_store()
    reporter = GapReporter(client.config)
    groupings = []

    for run in client.list_runs():
        if not run.investigation_id:
            continue

        scenario = client.get_scenario(run.scenario_id)
        if not scenario:
            continue

        results = store.list_results(run.run_id)
        report = reporter.build_report(
            run.run_id,
            run.scenario_id,
            results,
            investigation_id=run.investigation_id,
            hypothesis_id=run.hypothesis_id,
        )

        object_refs = [f"course-of-action--{run.run_id}"]
        object_refs += [f"sighting--{r.result_id}" for r in results]
        if report.gaps:
            object_refs.append(f"note--{report.gap_id}")

        groupings.append(
            build_grouping(
                run.run_id,
                run.investigation_id,
                object_refs,
                hypothesis_id=run.hypothesis_id,
                created=run.started_at,
            )
        )
    return groupings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stamp(stix_obj: dict[str, Any], run: Any) -> None:
    """Apply investigation context properties to a STIX object in-place."""
    from redgnat.feedback.investigation_context import apply_investigation_context

    apply_investigation_context(
        stix_obj,
        run.investigation_id,
        hypothesis_id=run.hypothesis_id,
        link_type="confirmed",
    )


def _run_to_stix_coa(run: Any, scenario: Any, results: list[Any]) -> dict:
    from datetime import datetime, timezone

    status_counts: dict[str, int] = {}
    for r in results:
        status_counts[r.status.value] = status_counts.get(r.status.value, 0) + 1

    coa: dict[str, Any] = {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": f"course-of-action--{run.run_id}",
        "created": (run.started_at or datetime.now(timezone.utc)).isoformat(),
        "modified": (run.completed_at or datetime.now(timezone.utc)).isoformat(),
        "name": f"CART Run: {scenario.name}",
        "description": (
            f"Automated red team emulation run. "
            f"Techniques: {len(results)}. "
            f"Status breakdown: {status_counts}"
        ),
        "x_redgnat_metadata": {
            "run_id": run.run_id,
            "scenario_id": run.scenario_id,
            "feed_id": scenario.feed_id,
            "status": run.status.value,
            "triggered_by": run.triggered_by,
            "technique_results": status_counts,
        },
    }
    if run.investigation_id:
        _stamp(coa, run)
    return coa
