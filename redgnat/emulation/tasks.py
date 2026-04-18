"""
Celery task definitions for async emulation execution.

Workers are started with:
    celery -A redgnat.emulation.tasks worker --loglevel=info -Q redgnat

The beat scheduler (celery beat) drives periodic intel ingestion:
    celery -A redgnat.emulation.tasks beat --loglevel=info
"""
from __future__ import annotations

import logging
import os

from celery import Celery

logger = logging.getLogger(__name__)

# Celery app — configured from environment / RedGNAT config
_redis_url = os.environ.get("REDGNAT_REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "redgnat",
    broker=_redis_url,
    backend=_redis_url,
    include=["redgnat.emulation.tasks"],
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_default_queue="redgnat",
    task_routes={"redgnat.emulation.tasks.*": {"queue": "redgnat"}},
    # Beat schedule for continuous intel polling
    beat_schedule={
        "ingest-gnat-intel": {
            "task": "redgnat.emulation.tasks.ingest_intel_task",
            "schedule": 300.0,  # every 5 minutes; overridden by config
            "args": [],
        },
    },
)


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def run_scenario_task(self, run_id: str) -> dict:
    """
    Execute an emulation run asynchronously.

    Parameters
    ----------
    run_id : str
        ID of the EmulationRun to execute (must exist in the DB).

    Returns
    -------
    dict
        Summary of the completed run.
    """
    from redgnat.client import RedGNATClient

    client = RedGNATClient()
    store = client._get_store()

    run = store.get_run(run_id)
    if run is None:
        logger.error("run_scenario_task: run %s not found", run_id)
        return {"error": f"run {run_id} not found"}

    scenario = store.get_scenario(run.scenario_id)
    if scenario is None:
        logger.error("run_scenario_task: scenario %s not found", run.scenario_id)
        return {"error": f"scenario {run.scenario_id} not found"}

    from redgnat.emulation.runner import EmulationRunner

    runner = EmulationRunner(client.config)
    try:
        results = runner.execute(run, scenario)
        return {
            "run_id": run_id,
            "scenario_id": run.scenario_id,
            "techniques_executed": len(results),
            "status": run.status.value,
        }
    except Exception as exc:
        logger.exception("run_scenario_task failed for run %s: %s", run_id, exc)
        raise self.retry(exc=exc)


@app.task
def ingest_intel_task() -> dict:
    """
    Poll GNAT and SandGNAT for new intel and enqueue scenarios.

    Triggered by Celery beat on the configured poll_interval_seconds.
    """
    from redgnat.client import RedGNATClient

    client = RedGNATClient()
    feeds = client.ingest_latest()
    logger.info("ingest_intel_task: ingested %d new feed records", len(feeds))

    # Auto-run newly created active scenarios
    enqueued = 0
    for scenario in client.list_scenarios():
        from redgnat.orm.models import ScenarioStatus

        if scenario.status == ScenarioStatus.ACTIVE:
            existing_runs = client.list_runs(scenario_id=scenario.scenario_id)
            if not existing_runs:
                client.run_scenario(
                    scenario.scenario_id,
                    triggered_by="intel_event",
                    async_=True,
                )
                enqueued += 1

    return {"feeds_ingested": len(feeds), "runs_enqueued": enqueued}
