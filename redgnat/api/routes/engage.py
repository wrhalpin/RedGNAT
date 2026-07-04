# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Engagement management routes — Phase 2 gate, kill switch, and status."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Header, HTTPException

router = APIRouter(tags=["engagement"])

_KILL_KEY_HEADER = "X-Kill-Key"


def _get_config() -> Any:
    from redgnat.config import RedGNATConfig
    return RedGNATConfig()


def _require_kill_key(x_kill_key: str | None, *, deny_if_unset: bool = False) -> None:
    """
    Raise 403 if the kill-key header is missing or wrong.

    When ``deny_if_unset`` is True the request is denied unless
    ``REDGNAT_KILL_KEY`` is configured — used for the *dangerous* direction
    (minting a Phase 2 engagement token), which must never be reachable with
    only the general API key. The kill/reset endpoints keep the permissive
    default so an operator is never locked out of the brakes.
    """
    import os
    expected = os.environ.get("REDGNAT_KILL_KEY", "")
    if not expected:
        if deny_if_unset:
            raise HTTPException(
                status_code=403,
                detail=(
                    "REDGNAT_KILL_KEY must be configured before a Phase 2 "
                    "engagement can be authorized via the API."
                ),
            )
        return  # not configured — open (operator accepts the risk)
    if x_kill_key != expected:
        raise HTTPException(status_code=403, detail="Invalid or missing X-Kill-Key")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@router.get("/engage/status")
async def engagement_status() -> dict:
    """Return the current state of all engagement gates and the kill switch."""
    from redgnat.engagement.gate import EngagementGate

    config = _get_config()
    gate = EngagementGate(config)
    return gate.status()


# ---------------------------------------------------------------------------
# Authorization (create / revoke engagement token)
# ---------------------------------------------------------------------------


@router.post("/engage/authorize")
async def authorize_engagement(
    body: dict = Body(...),
    x_kill_key: str | None = Header(default=None, alias=_KILL_KEY_HEADER),
) -> dict:
    """
    Create a time-bounded engagement token (Gate 3).

    Gates 1 and 2 must already be satisfied (config flag + env var), and the
    privileged ``X-Kill-Key`` header is required — the same elevated key that
    guards the kill switch — so a holder of only the general API key cannot
    mint a Phase 2 engagement.

    Request body
    ------------
    operator : str
        Identity of the authorizing operator.
    duration_hours : float
        Token lifetime in hours (e.g. 4.0 for a four-hour window).
    """
    _require_kill_key(x_kill_key, deny_if_unset=True)

    from redgnat.engagement.gate import EngagementGate

    operator = body.get("operator", "")
    duration_hours = float(body.get("duration_hours", 0))
    if not operator:
        raise HTTPException(status_code=422, detail="operator is required")
    if duration_hours <= 0 or duration_hours > 24:
        raise HTTPException(
            status_code=422, detail="duration_hours must be > 0 and <= 24"
        )

    config = _get_config()
    gate = EngagementGate(config)
    try:
        token = gate.authorize(operator=operator, duration_hours=duration_hours)
    except (PermissionError, RuntimeError) as exc:
        # Gate 1/2 unsatisfied → not authorized.
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "token_id": token.token_id,
        "operator": token.operator,
        "expires_at": token.expires_at.isoformat(),
        "remaining_seconds": token.remaining_seconds,
    }


@router.delete("/engage/authorize")
async def revoke_engagement(
    x_kill_key: str | None = Header(default=None, alias=_KILL_KEY_HEADER),
) -> dict:
    """Revoke the active engagement token immediately."""
    _require_kill_key(x_kill_key)

    from redgnat.engagement.gate import EngagementGate

    config = _get_config()
    EngagementGate(config).revoke_token()
    return {"revoked": True}


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@router.post("/engage/kill")
async def activate_kill_switch(
    body: dict = Body(default={}),
    x_kill_key: str | None = Header(default=None, alias=_KILL_KEY_HEADER),
) -> dict:
    """
    Activate the global kill switch.

    Requires the X-Kill-Key header when REDGNAT_KILL_KEY is configured.

    Request body (all optional)
    ---------------------------
    reason : str
    operator : str
    """
    _require_kill_key(x_kill_key)

    from redgnat.engagement.kill_switch import KillSwitch

    config = _get_config()
    report = KillSwitch(config).activate(
        reason=body.get("reason", ""),
        operator=body.get("operator", "api"),
    )
    return report


@router.delete("/engage/kill")
async def reset_kill_switch(
    body: dict = Body(default={}),
    x_kill_key: str | None = Header(default=None, alias=_KILL_KEY_HEADER),
) -> dict:
    """
    Reset (clear) the kill switch.

    Does NOT restart workers or re-queue tasks — the operator must do
    that explicitly after reviewing what happened.
    """
    _require_kill_key(x_kill_key)

    from redgnat.engagement.kill_switch import KillSwitch

    config = _get_config()
    KillSwitch(config).reset(operator=body.get("operator", "api"))
    return {"reset": True}
