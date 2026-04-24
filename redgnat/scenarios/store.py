# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
ScenarioStore — all PostgreSQL persistence for RedGNAT.

The single source of truth for database access. No other module writes to
the database directly (mirrors SandGNAT's persistence.py convention).
"""
from __future__ import annotations

import json
import logging
from typing import Any

from redgnat.config import RedGNATConfig
from redgnat.orm.models import (
    EmulationRun,
    EmulationScenario,
    IntelFeed,
    RunStatus,
    ScenarioStatus,
    TechniqueResult,
)

logger = logging.getLogger(__name__)


class ScenarioStore:
    """
    PostgreSQL-backed store for all RedGNAT entities.

    Uses psycopg3 with a simple connection-per-operation model.
    All SQL is in this module — never scatter queries elsewhere.

    Parameters
    ----------
    config : RedGNATConfig
        Must provide ``db_url``.
    """

    def __init__(self, config: RedGNATConfig) -> None:
        self._db_url = config.db_url
        self._conn: Any = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def _get_conn(self) -> Any:
        if self._conn is None or self._conn.closed:
            try:
                import psycopg  # type: ignore[import]

                self._conn = psycopg.connect(self._db_url)
            except ImportError as exc:
                raise RuntimeError(
                    "psycopg not installed. Run: pip install 'psycopg[binary]'"
                ) from exc
        return self._conn

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()

    # ------------------------------------------------------------------
    # IntelFeed
    # ------------------------------------------------------------------
    def upsert_feed(self, feed: IntelFeed) -> None:
        sql = """
            INSERT INTO intel_feeds (
                feed_id, source, source_ref_id, stix_bundle,
                campaign_name, attack_pattern_ids, confidence, ingested_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (feed_id) DO UPDATE SET
                stix_bundle = EXCLUDED.stix_bundle,
                attack_pattern_ids = EXCLUDED.attack_pattern_ids,
                confidence = EXCLUDED.confidence
        """
        with self._get_conn() as conn:
            conn.execute(
                sql,
                (
                    feed.feed_id,
                    feed.source.value,
                    feed.source_ref_id,
                    json.dumps(feed.stix_bundle),
                    feed.campaign_name,
                    feed.attack_pattern_ids,
                    feed.confidence,
                    feed.ingested_at,
                ),
            )

    def get_feed(self, feed_id: str) -> IntelFeed | None:
        sql = "SELECT * FROM intel_feeds WHERE feed_id = %s"
        with self._get_conn() as conn:
            row = conn.execute(sql, (feed_id,)).fetchone()
        return self._row_to_feed(row) if row else None

    @staticmethod
    def _row_to_feed(row: Any) -> IntelFeed:
        from redgnat.orm.models import IntelSource

        return IntelFeed(
            feed_id=row[0],
            source=IntelSource(row[1]),
            source_ref_id=row[2],
            stix_bundle=json.loads(row[3]) if isinstance(row[3], str) else (row[3] or {}),
            campaign_name=row[4],
            attack_pattern_ids=list(row[5]) if row[5] else [],
            confidence=float(row[6]),
            ingested_at=row[7],
        )

    # ------------------------------------------------------------------
    # EmulationScenario
    # ------------------------------------------------------------------
    def upsert_scenario(self, scenario: EmulationScenario) -> None:
        sql = """
            INSERT INTO emulation_scenarios (
                scenario_id, name, description, feed_id,
                technique_ids, scope_overrides, status, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (scenario_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                technique_ids = EXCLUDED.technique_ids,
                scope_overrides = EXCLUDED.scope_overrides,
                status = EXCLUDED.status,
                updated_at = EXCLUDED.updated_at
        """
        with self._get_conn() as conn:
            conn.execute(
                sql,
                (
                    scenario.scenario_id,
                    scenario.name,
                    scenario.description,
                    scenario.feed_id,
                    scenario.technique_ids,
                    json.dumps(scenario.scope_overrides),
                    scenario.status.value,
                    scenario.created_at,
                    scenario.updated_at,
                ),
            )

    def get_scenario(self, scenario_id: str) -> EmulationScenario | None:
        sql = "SELECT * FROM emulation_scenarios WHERE scenario_id = %s"
        with self._get_conn() as conn:
            row = conn.execute(sql, (scenario_id,)).fetchone()
        return self._row_to_scenario(row) if row else None

    def list_scenarios(
        self,
        status: ScenarioStatus | None = None,
        limit: int = 100,
    ) -> list[EmulationScenario]:
        if status:
            sql = "SELECT * FROM emulation_scenarios WHERE status = %s ORDER BY created_at DESC LIMIT %s"
            params = (status.value, limit)
        else:
            sql = "SELECT * FROM emulation_scenarios ORDER BY created_at DESC LIMIT %s"
            params = (limit,)
        with self._get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_scenario(r) for r in rows]

    @staticmethod
    def _row_to_scenario(row: Any) -> EmulationScenario:
        return EmulationScenario(
            scenario_id=row[0],
            name=row[1],
            description=row[2],
            feed_id=row[3],
            technique_ids=list(row[4]) if row[4] else [],
            scope_overrides=json.loads(row[5]) if isinstance(row[5], str) else (row[5] or {}),
            status=ScenarioStatus(row[6]),
            created_at=row[7],
            updated_at=row[8],
        )

    # ------------------------------------------------------------------
    # EmulationRun
    # ------------------------------------------------------------------
    def upsert_run(self, run: EmulationRun) -> None:
        sql = """
            INSERT INTO emulation_runs (
                run_id, scenario_id, celery_task_id, status,
                started_at, completed_at, triggered_by,
                investigation_id, hypothesis_id, investigation_tenant_id,
                investigation_validation_pending
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (run_id) DO UPDATE SET
                celery_task_id = EXCLUDED.celery_task_id,
                status = EXCLUDED.status,
                started_at = EXCLUDED.started_at,
                completed_at = EXCLUDED.completed_at,
                investigation_id = EXCLUDED.investigation_id,
                hypothesis_id = EXCLUDED.hypothesis_id,
                investigation_tenant_id = EXCLUDED.investigation_tenant_id,
                investigation_validation_pending = EXCLUDED.investigation_validation_pending
        """
        with self._get_conn() as conn:
            conn.execute(
                sql,
                (
                    run.run_id,
                    run.scenario_id,
                    run.celery_task_id,
                    run.status.value,
                    run.started_at,
                    run.completed_at,
                    run.triggered_by,
                    run.investigation_id,
                    run.hypothesis_id,
                    run.investigation_tenant_id,
                    run.investigation_validation_pending,
                ),
            )

    def get_run(self, run_id: str) -> EmulationRun | None:
        sql = "SELECT * FROM emulation_runs WHERE run_id = %s"
        with self._get_conn() as conn:
            row = conn.execute(sql, (run_id,)).fetchone()
        return self._row_to_run(row) if row else None

    def list_runs(
        self,
        scenario_id: str | None = None,
        investigation_id: str | None = None,
        limit: int = 50,
    ) -> list[EmulationRun]:
        conditions = []
        params: list = []
        if scenario_id:
            conditions.append("scenario_id = %s")
            params.append(scenario_id)
        if investigation_id:
            conditions.append("investigation_id = %s")
            params.append(investigation_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        sql = f"SELECT * FROM emulation_runs {where} ORDER BY started_at DESC NULLS LAST LIMIT %s"
        with self._get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_run(r) for r in rows]

    @staticmethod
    def _row_to_run(row: Any) -> EmulationRun:
        # Columns 0-6: original schema; 7-10: added by migration 003
        return EmulationRun(
            run_id=row[0],
            scenario_id=row[1],
            celery_task_id=row[2],
            status=RunStatus(row[3]),
            started_at=row[4],
            completed_at=row[5],
            triggered_by=row[6],
            investigation_id=row[7] if len(row) > 7 else None,
            hypothesis_id=row[8] if len(row) > 8 else None,
            investigation_tenant_id=row[9] if len(row) > 9 else None,
            investigation_validation_pending=bool(row[10]) if len(row) > 10 else False,
        )

    # ------------------------------------------------------------------
    # TechniqueResult
    # ------------------------------------------------------------------
    def insert_result(self, result: TechniqueResult) -> None:
        sql = """
            INSERT INTO technique_results (
                result_id, run_id, scenario_id, feed_id,
                technique_id, tactic, status, findings, evidence, error, executed_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (result_id) DO NOTHING
        """
        with self._get_conn() as conn:
            conn.execute(
                sql,
                (
                    result.result_id,
                    result.run_id,
                    result.scenario_id,
                    result.feed_id,
                    result.technique_id,
                    result.tactic,
                    result.status.value,
                    json.dumps(result.findings),
                    json.dumps(result.evidence),
                    result.error,
                    result.executed_at,
                ),
            )

    def list_results(self, run_id: str) -> list[TechniqueResult]:
        sql = "SELECT * FROM technique_results WHERE run_id = %s ORDER BY executed_at"
        with self._get_conn() as conn:
            rows = conn.execute(sql, (run_id,)).fetchall()
        return [self._row_to_result(r) for r in rows]

    @staticmethod
    def _row_to_result(row: Any) -> TechniqueResult:
        from redgnat.orm.models import ResultStatus

        return TechniqueResult(
            result_id=row[0],
            run_id=row[1],
            scenario_id=row[2],
            feed_id=row[3],
            technique_id=row[4],
            tactic=row[5],
            status=ResultStatus(row[6]),
            findings=json.loads(row[7]) if isinstance(row[7], str) else (row[7] or []),
            evidence=json.loads(row[8]) if isinstance(row[8], str) else (row[8] or []),
            error=row[9],
            executed_at=row[10],
        )
