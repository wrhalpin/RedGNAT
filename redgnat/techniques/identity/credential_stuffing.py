"""
Credential Stuffing — T1110.004

Replays previously-breached username:password pairs against in-scope IdPs.

Emulation controls:
- Only tests accounts listed in scope.target_accounts
- Credential list is filtered to only include in-scope accounts before use
- Plaintext passwords are never persisted; only redacted hints are stored
- Rate-limited with jitter

Use this to measure:
- Whether compromised credentials from external breaches are still valid
- Whether breach detection (HIBP-style signals, Entra ID Leaked Credential risk) fires
- Whether MFA or Conditional Access blocks replay attempts
"""
from __future__ import annotations

import logging
import random
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext
from redgnat.techniques.identity.base import (
    AuthAttemptResult,
    EntraAuthClient,
    LDAPAuthClient,
    OktaAuthClient,
    _jitter_sleep,
    _redact_password,
)

logger = logging.getLogger(__name__)


class CredentialStuffingTechnique(Technique):
    """
    ATT&CK T1110.004 — Credential Stuffing.

    Tests username:password pairs from a breach credential list against
    configured IdPs. Only pairs where the username matches a scope.target_account
    are tested.

    Parameters (ctx.params)
    -----------------------
    credential_pairs : list[dict]
        List of {"username": ..., "password": ...} dicts.
        Only pairs matching scope.target_accounts are executed.
    providers : list[str]
        IdPs to test against (default: all configured).
    shuffle : bool
        Randomise attempt order (default: True).
    """

    technique_id = "T1110.004"
    tactic = "credential-access"
    name = "Credential Stuffing"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        credential_pairs: list[dict] = ctx.params.get("credential_pairs", [])
        providers: list[str] = ctx.params.get("providers", ["entra", "okta", "ldap"])
        shuffle: bool = ctx.params.get("shuffle", True)

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would test {len(credential_pairs)} credential pair(s) against {providers}",
            )

        if not credential_pairs:
            return self._blocked_result(ctx, "No credential_pairs provided in ctx.params")

        # Filter to only in-scope test accounts
        scoped_pairs = [
            p for p in credential_pairs
            if ctx.scope.allows_account(p.get("username", ""))
        ]

        if not scoped_pairs:
            return self._blocked_result(
                ctx,
                f"None of the {len(credential_pairs)} credential pairs match "
                f"scope.target_accounts — aborting"
            )

        if shuffle:
            random.shuffle(scoped_pairs)

        all_results: list[AuthAttemptResult] = []
        locked_accounts: set[str] = set()

        for pair in scoped_pairs:
            username = pair.get("username", "")
            password = pair.get("password", "")

            if username in locked_accounts:
                continue

            for provider in providers:
                result = self._attempt(cfg, provider, username, password)
                all_results.append(result)

                if result.locked_out:
                    logger.warning("CredentialStuffing: %s locked on %s", username, provider)
                    locked_accounts.add(username)
                    break

                if result.success:
                    logger.warning(
                        "CredentialStuffing: SUCCESSFUL stuffed auth for %s on %s [run=%s]",
                        username,
                        provider,
                        ctx.run_id,
                    )

                _jitter_sleep(60.0 / ctx.scope.max_rate_per_minute)

        findings = self._build_findings(all_results, scoped_pairs)
        status = (
            ResultStatus.SUCCESS
            if any(r.success for r in all_results)
            else ResultStatus.PARTIAL
        )
        return self._make_result(ctx, status, findings)

    def _attempt(
        self, cfg: Any, provider: str, username: str, password: str
    ) -> AuthAttemptResult:
        if provider == "entra" and cfg.entra_tenant_id:
            return EntraAuthClient(cfg.entra_tenant_id, cfg.entra_client_id).attempt(
                username, password
            )
        elif provider == "okta" and cfg.okta_base_url:
            return OktaAuthClient(cfg.okta_base_url).attempt(username, password)
        elif provider == "ldap" and cfg.ldap_server:
            return LDAPAuthClient(cfg.ldap_server, cfg.ldap_port, cfg.ldap_use_ssl).attempt(
                username, password
            )
        return AuthAttemptResult(
            provider=provider,
            account=username,
            password_hint=_redact_password(password),
            success=False,
            locked_out=False,
            mfa_required=False,
            error_code="provider_not_configured",
            http_status=None,
            raw_response_snippet=None,
        )

    @staticmethod
    def _build_findings(results: list[AuthAttemptResult], pairs: list[dict]) -> list[dict]:
        successes = [r for r in results if r.success]
        return [
            {
                "attack": "credential_stuffing",
                "pairs_tested": len(pairs),
                "total_attempts": len(results),
                "successful_authentications": len(successes),
                "mfa_blocked": len([r for r in results if r.mfa_required]),
                "accounts_locked": len({r.account for r in results if r.locked_out}),
                "successful_accounts": [r.account for r in successes],
                "attempts": [
                    {
                        "provider": r.provider,
                        "account": r.account,
                        "password_hint": r.password_hint,
                        "success": r.success,
                        "mfa_required": r.mfa_required,
                        "locked_out": r.locked_out,
                        "error_code": r.error_code,
                    }
                    for r in results
                ],
            }
        ]
