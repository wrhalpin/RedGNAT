-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Bill Halpin
-- RedGNAT Initial Schema
-- Migration 001 — forward-only, never edit after deployment
-- Apply with: psql $REDGNAT_DB_URL -f migrations/001_initial_schema.sql

BEGIN;

-- Intel feeds ingested from GNAT and SandGNAT
CREATE TABLE IF NOT EXISTS intel_feeds (
    feed_id          UUID PRIMARY KEY,
    source           TEXT NOT NULL,               -- 'gnat' | 'sandgnat'
    source_ref_id    TEXT NOT NULL,               -- STIX ID or SandGNAT analysis_id
    stix_bundle      JSONB NOT NULL DEFAULT '{}',
    campaign_name    TEXT,
    attack_pattern_ids TEXT[] NOT NULL DEFAULT '{}',
    confidence       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_intel_feeds_source ON intel_feeds (source);
CREATE INDEX IF NOT EXISTS idx_intel_feeds_source_ref ON intel_feeds (source_ref_id);
CREATE INDEX IF NOT EXISTS idx_intel_feeds_ingested ON intel_feeds (ingested_at DESC);

-- Emulation scenarios built from intel feeds
CREATE TABLE IF NOT EXISTS emulation_scenarios (
    scenario_id      UUID PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    feed_id          UUID REFERENCES intel_feeds (feed_id),
    technique_ids    TEXT[] NOT NULL DEFAULT '{}',
    scope_overrides  JSONB NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'active' | 'archived'
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scenarios_feed ON emulation_scenarios (feed_id);
CREATE INDEX IF NOT EXISTS idx_scenarios_status ON emulation_scenarios (status);
CREATE INDEX IF NOT EXISTS idx_scenarios_created ON emulation_scenarios (created_at DESC);

-- Emulation run records
CREATE TABLE IF NOT EXISTS emulation_runs (
    run_id           UUID PRIMARY KEY,
    scenario_id      UUID NOT NULL REFERENCES emulation_scenarios (scenario_id),
    celery_task_id   TEXT,
    status           TEXT NOT NULL DEFAULT 'queued',  -- 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    triggered_by     TEXT NOT NULL DEFAULT 'scheduler'
);

CREATE INDEX IF NOT EXISTS idx_runs_scenario ON emulation_runs (scenario_id);
CREATE INDEX IF NOT EXISTS idx_runs_status ON emulation_runs (status);
CREATE INDEX IF NOT EXISTS idx_runs_started ON emulation_runs (started_at DESC NULLS LAST);

-- Per-technique outcomes within a run
CREATE TABLE IF NOT EXISTS technique_results (
    result_id        UUID PRIMARY KEY,
    run_id           UUID NOT NULL REFERENCES emulation_runs (run_id),
    scenario_id      UUID NOT NULL REFERENCES emulation_scenarios (scenario_id),
    feed_id          UUID REFERENCES intel_feeds (feed_id),
    technique_id     TEXT NOT NULL,   -- ATT&CK ID, e.g. 'T1046'
    tactic           TEXT NOT NULL,
    status           TEXT NOT NULL,   -- 'success' | 'partial' | 'blocked' | 'detected' | 'error' | 'dry_run'
    findings         JSONB NOT NULL DEFAULT '[]',
    evidence         JSONB NOT NULL DEFAULT '[]',
    error            TEXT,
    executed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_results_run ON technique_results (run_id);
CREATE INDEX IF NOT EXISTS idx_results_technique ON technique_results (technique_id);
CREATE INDEX IF NOT EXISTS idx_results_status ON technique_results (status);
CREATE INDEX IF NOT EXISTS idx_results_executed ON technique_results (executed_at DESC);

COMMIT;
