"""
EngagementGate — three-factor Phase 2 activation check.

All three factors must be satisfied simultaneously for Phase 2 to proceed:

  1. Config flag  — phase2_enabled = true in [redgnat]
  2. Env variable — REDGNAT_PHASE2_UNLOCK is set and non-empty in the
                    process environment (injected at runtime, not baked
                    into config so it can't be accidentally inherited)
  3. Active token — a valid, unexpired EngagementToken exists in Redis
                    (created explicitly by an operator via CLI or API)

Failing any single gate blocks Phase 2 regardless of the other two.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_UNLOCK_ENV_VAR = "REDGNAT_PHASE2_UNLOCK"


class EngagementGate:
    """
    Checks the three-factor Phase 2 impasse.

    Parameters
    ----------
    config : RedGNATConfig
        Application configuration (provides gate 1 — phase2_enabled).
    """

    def __init__(self, config: Any) -> None:
        self.config = config

    def check(self) -> tuple[bool, str]:
        """
        Evaluate all three gates in order.

        Returns
        -------
        (authorized, reason) : tuple[bool, str]
            authorized — True only if all three gates pass.
            reason     — human-readable explanation of the first failed gate,
                         or a confirmation message if all pass.
        """
        # Gate 1 — config flag
        if not self.config.phase2_enabled:
            return False, (
                "Gate 1 failed: phase2_enabled is not set in [redgnat] config. "
                "Add 'phase2_enabled = true' to enable Phase 2."
            )

        # Gate 2 — environment variable present and non-empty
        unlock = os.environ.get(_UNLOCK_ENV_VAR, "").strip()
        if not unlock:
            return False, (
                f"Gate 2 failed: {_UNLOCK_ENV_VAR} is not set in the process environment. "
                "Inject the activation secret at runtime before starting the worker."
            )

        # Gate 3 — valid engagement token in Redis
        try:
            from redgnat.engagement.token import EngagementToken

            redis = self._redis()
            token = EngagementToken.load(redis)
        except Exception as exc:
            return False, f"Gate 3 failed: could not reach Redis to check token: {exc}"

        if token is None:
            return False, (
                "Gate 3 failed: no active engagement token. "
                "Run: redgnat engage --duration <hours> --operator <name>"
            )

        if not token.is_valid:
            return False, (
                f"Gate 3 failed: engagement token expired at {token.expires_at.isoformat()} "
                f"(operator: {token.operator}). Create a new token to continue."
            )

        remaining_min = int(token.remaining_seconds / 60)
        return True, (
            f"All gates passed — Phase 2 authorized until {token.expires_at.isoformat()} "
            f"({remaining_min} min remaining, operator: {token.operator})"
        )

    def authorize(self, operator: str, duration_hours: float) -> "Any":
        """
        Generate and store a new engagement token (gate 1 + 2 must already pass).

        Returns the created EngagementToken.
        Raises RuntimeError if gate 1 or gate 2 fails.
        """
        from redgnat.engagement.token import EngagementToken

        if not self.config.phase2_enabled:
            raise RuntimeError(
                "Cannot authorize: phase2_enabled is not set in config."
            )

        unlock = os.environ.get(_UNLOCK_ENV_VAR, "").strip()
        if not unlock:
            raise RuntimeError(
                f"Cannot authorize: {_UNLOCK_ENV_VAR} is not set in the process environment."
            )

        if duration_hours <= 0 or duration_hours > 24:
            raise ValueError("Engagement duration must be between 0 and 24 hours.")

        token = EngagementToken.create(operator=operator, duration_hours=duration_hours)
        redis = self._redis()
        token.store(redis)

        logger.warning(
            "PHASE2 AUTHORIZED: operator=%s duration=%.1fh expires=%s token=%s",
            operator,
            duration_hours,
            token.expires_at.isoformat(),
            token.token_id,
        )
        return token

    def revoke_token(self) -> None:
        """Revoke the active engagement token, immediately invalidating gate 3."""
        from redgnat.engagement.token import EngagementToken

        EngagementToken.revoke(self._redis())
        logger.warning("PHASE2 TOKEN REVOKED")

    def status(self) -> dict:
        """Return a structured dict describing the current gate state."""
        from redgnat.engagement.token import EngagementToken
        from redgnat.engagement.kill_switch import KillSwitch

        gate1 = self.config.phase2_enabled
        gate2 = bool(os.environ.get(_UNLOCK_ENV_VAR, "").strip())

        token_info: dict = {"active": False}
        try:
            token = EngagementToken.load(self._redis())
            if token and token.is_valid:
                token_info = {
                    "active": True,
                    "token_id": token.token_id,
                    "operator": token.operator,
                    "expires_at": token.expires_at.isoformat(),
                    "remaining_minutes": int(token.remaining_seconds / 60),
                }
        except Exception:
            token_info = {"active": False, "error": "redis unavailable"}

        ks = KillSwitch(self.config)
        kill_info = ks.status()

        authorized, reason = self.check()
        return {
            "phase2_authorized": authorized,
            "reason": reason,
            "gates": {
                "config_flag": gate1,
                "unlock_env_set": gate2,
                "token": token_info,
            },
            "kill_switch": kill_info,
        }

    def _redis(self) -> Any:
        import redis as redis_lib

        return redis_lib.from_url(self.config.redis_url)
