-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Bill Halpin
-- Migration 003 — investigation context
-- Adds nullable investigation/hypothesis columns to emulation_runs so each run
-- can be linked to a GNAT investigation and (optionally) a specific Hypothesis.
-- link_type is always "confirmed" for engagement-driven runs; the column is
-- omitted in favour of a code-level constant (no column needed for Phase 1-4).
-- Forward-only — never edit after deployment.
-- Apply with: psql $REDGNAT_DB_URL -f migrations/003_investigation_context.sql

BEGIN;

ALTER TABLE emulation_runs
    ADD COLUMN IF NOT EXISTS investigation_id            TEXT,
    ADD COLUMN IF NOT EXISTS hypothesis_id               TEXT,
    ADD COLUMN IF NOT EXISTS investigation_tenant_id     TEXT,
    ADD COLUMN IF NOT EXISTS investigation_validation_pending
                                                         BOOLEAN NOT NULL DEFAULT FALSE;

-- Partial indexes: only index rows that actually have an investigation
CREATE INDEX IF NOT EXISTS idx_runs_investigation_id
    ON emulation_runs (investigation_id)
    WHERE investigation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_runs_hypothesis_id
    ON emulation_runs (hypothesis_id)
    WHERE hypothesis_id IS NOT NULL;

COMMIT;
