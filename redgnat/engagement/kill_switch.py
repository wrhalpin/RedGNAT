# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
KillSwitch — the big red button.

Activating the kill switch:
  1. Sets redgnat:kill:active in Redis (checked before every technique step)
  2. Writes a durable record to Postgres (survives Redis restart)
  3. Purges the Celery task queue (removes all pending tasks)
  4. Closes any active GoPhish campaigns
  5. Pushes a CRITICAL STIX Note to GNAT

The flag persists across worker restarts — workers check Postgres on startup
and refuse Phase 2 tasks until an operator explicitly resets the switch via
`redgnat kill --reset` or DELETE /engage/kill.

Paths to the kill switch (in order of preference):
  • redgnat kill                    — CLI (works without API server)
  • POST /api/v1/engage/kill        — REST API (requires X-Kill-Key header)
  • redis-cli SET redgnat:kill:active 1  — direct Redis (nuclear option)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_REDIS_KEY_ACTIVE = "redgnat:kill:active"
_REDIS_KEY_REASON = "redgnat:kill:reason"
_REDIS_KEY_OPERATOR = "redgnat:kill:operator"
_REDIS_KEY_TS = "redgnat:kill:activated_at"


class KillSwitch:
    """
    Manages the global kill state across Redis and Postgres.

    Parameters
    ----------
    config : RedGNATConfig
        Application configuration.
    """

    def __init__(self, config: Any) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Check
    # ------------------------------------------------------------------

    def is_active(self) -> bool:
        """
        Return True if the kill switch is active.

        Checks Redis first (fast path); falls back to Postgres if Redis
        is unavailable so a restarted worker still respects a prior kill.
        """
        try:
            redis = self._redis()
            if redis.get(_REDIS_KEY_ACTIVE):
                return True
        except Exception as exc:
            logger.warning("KillSwitch: Redis unavailable, checking Postgres: %s", exc)
            return self._postgres_is_active()
        return False

    def status(self) -> dict:
        """Return a dict describing the current kill state."""
        try:
            redis = self._redis()
            active = bool(redis.get(_REDIS_KEY_ACTIVE))
            if active:
                return {
                    "active": True,
                    "reason": (redis.get(_REDIS_KEY_REASON) or b"").decode(),
                    "operator": (redis.get(_REDIS_KEY_OPERATOR) or b"").decode(),
                    "activated_at": (redis.get(_REDIS_KEY_TS) or b"").decode(),
                }
        except Exception:
            pass
        return {"active": False}

    # ------------------------------------------------------------------
    # Activate
    # ------------------------------------------------------------------

    def activate(self, reason: str = "", operator: str = "") -> dict:
        """
        Activate the kill switch.

        Best-effort on steps 3-5: errors are logged but do not prevent
        steps 1-2 from completing.

        Returns
        -------
        dict
            Summary of what was done and any errors encountered.
        """
        now = datetime.now(timezone.utc).isoformat()
        report: dict = {
            "activated_at": now,
            "operator": operator,
            "reason": reason,
            "steps": {},
        }

        # Step 1 — Redis (immediate, checked by all workers on next step)
        try:
            redis = self._redis()
            redis.set(_REDIS_KEY_ACTIVE, "1")
            redis.set(_REDIS_KEY_REASON, reason)
            redis.set(_REDIS_KEY_OPERATOR, operator)
            redis.set(_REDIS_KEY_TS, now)
            report["steps"]["redis"] = "ok"
            logger.critical(
                "KILL SWITCH ACTIVATED — operator=%s reason=%r", operator, reason
            )
        except Exception as exc:
            report["steps"]["redis"] = f"FAILED: {exc}"
            logger.critical("KILL SWITCH: failed to set Redis flag: %s", exc)

        # Step 2 — Postgres (durable; survives Redis restart)
        try:
            self._postgres_record(reason=reason, operator=operator, activated_at=now)
            report["steps"]["postgres"] = "ok"
        except Exception as exc:
            report["steps"]["postgres"] = f"FAILED: {exc}"
            logger.error("KILL SWITCH: failed to write Postgres record: %s", exc)

        # Step 3 — Purge Celery queue (removes pending tasks)
        try:
            from redgnat.emulation.tasks import app as celery_app

            celery_app.control.purge()
            report["steps"]["celery_purge"] = "ok"
        except Exception as exc:
            report["steps"]["celery_purge"] = f"error: {exc}"
            logger.error("KILL SWITCH: Celery purge failed: %s", exc)

        # Step 4 — Close active GoPhish campaigns
        try:
            closed = self._close_gophish_campaigns()
            report["steps"]["gophish"] = f"closed {closed} campaign(s)"
        except Exception as exc:
            report["steps"]["gophish"] = f"error: {exc}"
            logger.error("KILL SWITCH: GoPhish close failed: %s", exc)

        # Step 5 — Push STIX Note to GNAT
        try:
            self._notify_gnat(reason=reason, operator=operator, activated_at=now)
            report["steps"]["gnat_notify"] = "ok"
        except Exception as exc:
            report["steps"]["gnat_notify"] = f"error: {exc}"
            logger.warning("KILL SWITCH: GNAT notification failed: %s", exc)

        return report

    # ------------------------------------------------------------------
    # Reset (clears the kill flag — requires explicit operator action)
    # ------------------------------------------------------------------

    def reset(self, operator: str = "") -> None:
        """
        Clear the kill switch.

        Does NOT restart any workers or re-queue any tasks — that is the
        operator's explicit responsibility after reviewing what happened.
        """
        try:
            redis = self._redis()
            redis.delete(_REDIS_KEY_ACTIVE, _REDIS_KEY_REASON, _REDIS_KEY_OPERATOR, _REDIS_KEY_TS)
        except Exception as exc:
            logger.error("KillSwitch.reset: Redis clear failed: %s", exc)

        try:
            self._postgres_clear(cleared_by=operator)
        except Exception as exc:
            logger.error("KillSwitch.reset: Postgres clear failed: %s", exc)

        logger.warning("KILL SWITCH RESET by operator=%s", operator)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _redis(self) -> Any:
        import redis as redis_lib

        return redis_lib.from_url(self.config.redis_url)

    def _postgres_is_active(self) -> bool:
        try:
            import psycopg

            with psycopg.connect(self.config.db_url) as conn:
                row = conn.execute(
                    "SELECT id FROM kill_switches WHERE cleared_at IS NULL ORDER BY activated_at DESC LIMIT 1"
                ).fetchone()
                return row is not None
        except Exception as exc:
            logger.error("KillSwitch: Postgres fallback failed: %s", exc)
            return False

    def _postgres_record(self, reason: str, operator: str, activated_at: str) -> None:
        import psycopg

        with psycopg.connect(self.config.db_url) as conn:
            conn.execute(
                """
                INSERT INTO kill_switches (activated_at, reason, operator)
                VALUES (%s, %s, %s)
                """,
                (activated_at, reason, operator),
            )
            conn.commit()

    def _postgres_clear(self, cleared_by: str) -> None:
        import psycopg

        now = datetime.now(timezone.utc).isoformat()
        with psycopg.connect(self.config.db_url) as conn:
            conn.execute(
                """
                UPDATE kill_switches
                SET cleared_at = %s, cleared_by = %s
                WHERE cleared_at IS NULL
                """,
                (now, cleared_by),
            )
            conn.commit()

    def _close_gophish_campaigns(self) -> int:
        """Close all active GoPhish campaigns. Returns count closed."""
        if not self.config.gophish_base_url or not self.config.gophish_api_key:
            return 0

        from redgnat.techniques.phishing.base import GoPhishClient

        client = GoPhishClient(self.config.gophish_base_url, self.config.gophish_api_key)
        campaigns = client.list_campaigns()
        closed = 0
        for c in campaigns:
            if c.get("status") in {"In progress", "Queued"}:
                cid = c.get("id")
                if cid:
                    client.complete_campaign(cid)
                    closed += 1
                    logger.warning("KILL SWITCH: closed GoPhish campaign %s", cid)
        return closed

    def _notify_gnat(self, reason: str, operator: str, activated_at: str) -> None:
        """Push a CRITICAL STIX Note to GNAT describing the kill event."""
        try:
            from gnat import GNATClient  # type: ignore[import]
        except ImportError:
            logger.warning("KillSwitch: GNAT not installed, skipping notification")
            return

        import uuid

        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": f"note--{uuid.uuid4()}",
            "created": activated_at,
            "modified": activated_at,
            "abstract": "RedGNAT KILL SWITCH ACTIVATED",
            "content": (
                f"RedGNAT engagement kill switch activated.\n"
                f"Operator: {operator}\n"
                f"Reason: {reason}\n"
                f"Time: {activated_at}\n\n"
                "All queued tasks have been purged. Active GoPhish campaigns closed. "
                "Workers will halt at next technique checkpoint. "
                "Manual review required before resuming operations."
            ),
            "authors": ["redgnat-kill-switch"],
            "labels": ["redgnat-kill", "critical-event"],
        }

        client = GNATClient(config_path=self.config.gnat_config_path)
        client.upsert_object(note)
