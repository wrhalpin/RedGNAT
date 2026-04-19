-- Migration 002: Engagement schema
-- Adds durable storage for kill switch events and engagement authorisations.
-- These tables are the Postgres half of the two-layer persistence model;
-- Redis holds the fast-path flags that workers check before each technique step.

CREATE TABLE IF NOT EXISTS kill_switches (
    id           SERIAL PRIMARY KEY,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason       TEXT        NOT NULL DEFAULT '',
    operator     TEXT        NOT NULL DEFAULT '',
    cleared_at   TIMESTAMPTZ,
    cleared_by   TEXT
);

-- Index for fast "is there an active kill?" query
CREATE INDEX IF NOT EXISTS idx_kill_switches_active
    ON kill_switches (activated_at DESC)
    WHERE cleared_at IS NULL;

CREATE TABLE IF NOT EXISTS engagement_authorizations (
    token_id     UUID        PRIMARY KEY,
    operator     TEXT        NOT NULL,
    duration_hours NUMERIC   NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    revoked_by   TEXT
);

CREATE INDEX IF NOT EXISTS idx_engagement_auth_active
    ON engagement_authorizations (expires_at DESC)
    WHERE revoked_at IS NULL;
