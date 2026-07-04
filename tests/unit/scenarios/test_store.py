# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""ScenarioStore tests with a mocked psycopg connection."""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from redgnat.config import RedGNATConfig
from redgnat.orm.models import (
    EmulationRun,
    EmulationScenario,
    IntelFeed,
    IntelSource,
    ResultStatus,
    RunStatus,
    ScenarioStatus,
    TechniqueResult,
)
from redgnat.scenarios.store import ScenarioStore

TS = datetime(2026, 1, 1, tzinfo=UTC)


def _conn(fetchone=None, fetchall=None):
    inner = MagicMock()
    cur = MagicMock()
    cur.fetchone.return_value = fetchone
    cur.fetchall.return_value = fetchall or []
    inner.execute.return_value = cur
    ctx = MagicMock()
    ctx.__enter__.return_value = inner
    ctx.__exit__.return_value = False
    return ctx, inner


@pytest.fixture
def store():
    return ScenarioStore(RedGNATConfig(path="/nonexistent.ini"))


class TestFeeds:
    def test_upsert_and_get_feed(self, store):
        feed = IntelFeed(
            feed_id="f1", source=IntelSource.GNAT, source_ref_id="c1",
            stix_bundle={"type": "bundle"}, campaign_name="c", attack_pattern_ids=["T1046"],
            confidence=0.7, ingested_at=TS,
        )
        ctx, inner = _conn()
        with patch.object(store, "_get_conn", return_value=ctx):
            store.upsert_feed(feed)
        assert inner.execute.called

        row = ("f1", "gnat", "c1", {"type": "bundle"}, "c", ["T1046"], 0.7, TS)
        ctx2, _ = _conn(fetchone=row)
        with patch.object(store, "_get_conn", return_value=ctx2):
            got = store.get_feed("f1")
        assert got.feed_id == "f1"
        assert got.source == IntelSource.GNAT
        assert got.attack_pattern_ids == ["T1046"]

    def test_get_feed_missing(self, store):
        ctx, _ = _conn(fetchone=None)
        with patch.object(store, "_get_conn", return_value=ctx):
            assert store.get_feed("x") is None

    def test_row_to_feed_json_string(self, store):
        row = ("f1", "gnat", "c1", '{"type": "bundle"}', None, None, 0.5, TS)
        feed = store._row_to_feed(row)
        assert feed.stix_bundle == {"type": "bundle"}
        assert feed.attack_pattern_ids == []


class TestScenarios:
    def test_upsert_and_get(self, store):
        scn = EmulationScenario(
            scenario_id="s1", name="n", description="d", feed_id="f1",
            technique_ids=["T1046"], scope_overrides={"dry_run": True},
            status=ScenarioStatus.ACTIVE, created_at=TS, updated_at=TS,
        )
        ctx, _ = _conn()
        with patch.object(store, "_get_conn", return_value=ctx):
            store.upsert_scenario(scn)

        row = ("s1", "n", "d", "f1", ["T1046"], {"dry_run": True}, "active", TS, TS)
        ctx2, _ = _conn(fetchone=row)
        with patch.object(store, "_get_conn", return_value=ctx2):
            got = store.get_scenario("s1")
        assert got.status == ScenarioStatus.ACTIVE
        assert got.scope_overrides == {"dry_run": True}

    def test_list_scenarios_filtered(self, store):
        row = ("s1", "n", "d", "f1", [], "{}", "active", TS, TS)
        ctx, inner = _conn(fetchall=[row])
        with patch.object(store, "_get_conn", return_value=ctx):
            out = store.list_scenarios(status=ScenarioStatus.ACTIVE)
        assert len(out) == 1

    def test_list_scenarios_all(self, store):
        ctx, _ = _conn(fetchall=[])
        with patch.object(store, "_get_conn", return_value=ctx):
            assert store.list_scenarios() == []


class TestRuns:
    def test_upsert_and_get_run(self, store):
        run = EmulationRun(
            run_id="r1", scenario_id="s1", status=RunStatus.RUNNING,
            started_at=TS, triggered_by="manual", investigation_id="IC-1",
            hypothesis_id="HYP-1", investigation_tenant_id="tn",
            investigation_validation_pending=True,
        )
        ctx, _ = _conn()
        with patch.object(store, "_get_conn", return_value=ctx):
            store.upsert_run(run)

        row = ("r1", "s1", None, "running", TS, None, "manual", "IC-1", "HYP-1", "tn", True)
        ctx2, _ = _conn(fetchone=row)
        with patch.object(store, "_get_conn", return_value=ctx2):
            got = store.get_run("r1")
        assert got.investigation_id == "IC-1"
        assert got.investigation_validation_pending is True

    def test_row_to_run_pre_migration(self, store):
        # Only the 7 original columns present -> investigation fields default
        row = ("r1", "s1", None, "queued", None, None, "scheduler")
        run = store._row_to_run(row)
        assert run.investigation_id is None
        assert run.investigation_validation_pending is False

    def test_list_runs_filters(self, store):
        row = ("r1", "s1", None, "completed", TS, TS, "manual", "IC-1", None, None, False)
        ctx, inner = _conn(fetchall=[row])
        with patch.object(store, "_get_conn", return_value=ctx):
            out = store.list_runs(scenario_id="s1", investigation_id="IC-1")
        assert out[0].run_id == "r1"
        # dynamic WHERE built with both filters
        sql = inner.execute.call_args[0][0]
        assert "scenario_id = %s" in sql and "investigation_id = %s" in sql


class TestResults:
    def test_insert_and_list_results(self, store):
        res = TechniqueResult(
            result_id="res1", run_id="r1", scenario_id="s1", feed_id="f1",
            technique_id="T1046", tactic="discovery", status=ResultStatus.SUCCESS,
            findings=[{"a": 1}], evidence=[], error=None, executed_at=TS,
        )
        ctx, _ = _conn()
        with patch.object(store, "_get_conn", return_value=ctx):
            store.insert_result(res)

        row = ("res1", "r1", "s1", "f1", "T1046", "discovery", "success",
               [{"a": 1}], [], None, TS)
        ctx2, _ = _conn(fetchall=[row])
        with patch.object(store, "_get_conn", return_value=ctx2):
            out = store.list_results("r1")
        assert out[0].technique_id == "T1046"
        assert out[0].status == ResultStatus.SUCCESS


def test_close_is_safe(store):
    store._conn = None
    store.close()  # no error when nothing open
