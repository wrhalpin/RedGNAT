# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RedGNATClient — top-level facade for all RedGNAT operations."""
from __future__ import annotations

import logging
from typing import Any

from redgnat.config import RedGNATConfig
from redgnat.orm.models import EmulationRun, EmulationScenario, IntelFeed, RunStatus

logger = logging.getLogger(__name__)


class RedGNATClient:
    """
    Top-level entry point for RedGNAT.

    Parameters
    ----------
    config_path : str | None
        Path to redgnat.ini; None uses the standard search order.

    Examples
    --------
    >>> client = RedGNATClient()
    >>> client.ingest_latest()           # pull new intel from GNAT + SandGNAT
    >>> scenarios = client.list_scenarios()
    >>> run = client.run_scenario(scenarios[0].scenario_id)
    """

    def __init__(self, config_path: str | None = None) -> None:
        self.config = RedGNATConfig(config_path)
        self._store: Any = None       # lazy: scenarios.store.ScenarioStore
        self._normalizer_inst: Any = None  # lazy: intake.normalizer.IntelNormalizer

    # ------------------------------------------------------------------
    # Intel ingestion
    # ------------------------------------------------------------------
    def ingest_latest(self) -> list[IntelFeed]:
        """
        Poll GNAT and SandGNAT for new intel and build scenarios.

        Returns
        -------
        list[IntelFeed]
            Newly ingested feed records.
        """
        from redgnat.intake.gnat_subscriber import GNATSubscriber
        from redgnat.intake.sandgnat_subscriber import SandGNATSubscriber
        from redgnat.intake.normalizer import IntelNormalizer
        from redgnat.scenarios.builder import ScenarioBuilder

        feeds: list[IntelFeed] = []
        normalizer = IntelNormalizer(self.config)
        builder = ScenarioBuilder(self.config)
        store = self._get_store()

        for sub in [GNATSubscriber(self.config), SandGNATSubscriber(self.config)]:
            for feed in sub.poll():
                scenario = normalizer.to_scenario(feed)
                if scenario:
                    store.upsert_feed(feed)
                    store.upsert_scenario(scenario)
                    logger.info(
                        "Ingested intel feed %s → scenario %s",
                        feed.feed_id,
                        scenario.scenario_id,
                    )
                feeds.append(feed)
        return feeds

    # ------------------------------------------------------------------
    # Scenario management
    # ------------------------------------------------------------------
    def list_scenarios(self) -> list[EmulationScenario]:
        return self._get_store().list_scenarios()

    def get_scenario(self, scenario_id: str) -> EmulationScenario | None:
        return self._get_store().get_scenario(scenario_id)

    # ------------------------------------------------------------------
    # Emulation
    # ------------------------------------------------------------------
    def run_scenario(
        self,
        scenario_id: str,
        triggered_by: str = "manual",
        async_: bool = True,
    ) -> EmulationRun:
        """
        Dispatch an emulation run for the given scenario.

        Parameters
        ----------
        scenario_id : str
            Scenario to execute.
        triggered_by : str
            Origin label ("manual", "scheduler", "intel_event").
        async_ : bool
            If True, enqueue as a Celery task and return immediately.
            If False, run synchronously (useful for tests and CLI).

        Returns
        -------
        EmulationRun
            Run record (status = QUEUED if async, COMPLETED if sync).
        """
        scenario = self._get_store().get_scenario(scenario_id)
        if scenario is None:
            raise ValueError(f"Scenario {scenario_id!r} not found")

        from redgnat.emulation.runner import EmulationRunner
        from redgnat.orm.models import EmulationRun

        run = EmulationRun(scenario_id=scenario_id, triggered_by=triggered_by)
        self._get_store().upsert_run(run)

        if async_:
            from redgnat.emulation.tasks import run_scenario_task

            task = run_scenario_task.delay(run.run_id)
            run.celery_task_id = task.id
            self._get_store().upsert_run(run)
            logger.info("Enqueued run %s (task %s)", run.run_id, task.id)
        else:
            runner = EmulationRunner(self.config)
            runner.execute(run, scenario)
            logger.info("Completed synchronous run %s", run.run_id)

        return run

    def list_runs(self, scenario_id: str | None = None) -> list[EmulationRun]:
        return self._get_store().list_runs(scenario_id=scenario_id)

    def get_run(self, run_id: str) -> EmulationRun | None:
        return self._get_store().get_run(run_id)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _get_store(self) -> Any:
        if self._store is None:
            from redgnat.scenarios.store import ScenarioStore

            self._store = ScenarioStore(self.config)
        return self._store

    def _normalizer(self) -> Any:
        if self._normalizer_inst is None:
            from redgnat.intake.normalizer import IntelNormalizer

            self._normalizer_inst = IntelNormalizer(self.config)
        return self._normalizer_inst
