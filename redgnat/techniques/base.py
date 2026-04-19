# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Technique ABC — base class and safe-harbor scope enforcement for all CART techniques.

Every technique module MUST:
1. Subclass Technique
2. Set technique_id, tactic, name, emulation_only = True
3. Call self._check_scope(ctx.scope, target) before ANY network activity
4. Return DRY_RUN result when ctx.scope.dry_run is True
"""
from __future__ import annotations

import abc
import ipaddress
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Scope:
    """
    Safe-harbor execution scope.

    Every technique validates targets against this before acting.
    A misconfigured scope is the most common source of security incidents
    in red team automation — treat this as a hard gate, not a suggestion.

    Parameters
    ----------
    target_ranges : list[str]
        CIDR blocks permitted for network-level techniques.
    excluded_ranges : list[str]
        CIDR blocks that are NEVER touched regardless of target_ranges.
    target_domains : list[str]
        DNS domains in scope for phishing and web techniques.
    excluded_domains : list[str]
        Domains that are NEVER targeted.
    target_accounts : list[str]
        UPNs / email addresses of dedicated test accounts.
        ONLY these accounts may be targeted by credential techniques.
    max_rate_per_minute : int
        Maximum requests per minute across all techniques.
    dry_run : bool
        If True, techniques log what they would do but never act.
    """

    target_ranges: list[str] = field(default_factory=list)
    excluded_ranges: list[str] = field(default_factory=list)
    target_domains: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    target_accounts: list[str] = field(default_factory=list)
    max_rate_per_minute: int = 30
    dry_run: bool = False

    def allows_ip(self, ip: str) -> bool:
        """Return True if ip is in scope (in target_ranges and not excluded)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        in_scope = any(
            addr in ipaddress.ip_network(r, strict=False) for r in self.target_ranges
        )
        excluded = any(
            addr in ipaddress.ip_network(r, strict=False) for r in self.excluded_ranges
        )
        return in_scope and not excluded

    def allows_domain(self, domain: str) -> bool:
        """Return True if domain is in scope."""
        domain = domain.lower().strip().rstrip(".")
        in_scope = any(
            domain == d or domain.endswith(f".{d}") for d in self.target_domains
        )
        excluded = any(
            domain == d or domain.endswith(f".{d}") for d in self.excluded_domains
        )
        return in_scope and not excluded

    def allows_account(self, upn: str) -> bool:
        """Return True only if upn is explicitly listed in target_accounts."""
        return upn.lower() in {a.lower() for a in self.target_accounts}

    def allows_cidr(self, cidr: str) -> bool:
        """Return True if any IP in the CIDR is in scope (conservative: requires full overlap)."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        return any(
            net.overlaps(ipaddress.ip_network(r, strict=False)) for r in self.target_ranges
        ) and not any(
            net.overlaps(ipaddress.ip_network(r, strict=False)) for r in self.excluded_ranges
        )


@dataclass
class TechniqueContext:
    """
    Runtime context passed to every technique execution.

    Parameters
    ----------
    run_id : str
        Parent EmulationRun ID.
    scenario_id : str
        Parent EmulationScenario ID.
    feed_id : str
        Source IntelFeed ID (for traceability).
    scope : Scope
        Safe-harbor scope — validated before every action.
    params : dict
        Per-step overrides (e.g. specific target range, custom wordlist path).
    started_at : datetime
        When this context was created.
    """

    run_id: str
    scenario_id: str
    feed_id: str
    scope: Scope
    params: dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class OutOfScopeError(Exception):
    """Raised when a technique target is not in the configured scope."""


class Technique(abc.ABC):
    """
    Abstract base class for all CART technique modules.

    Subclass contract:
    - Set class attributes: technique_id, tactic, name
    - Keep emulation_only = True (never exploit, only probe)
    - Call self._check_scope(scope, target) before ANY network activity
    - Return DRY_RUN result when scope.dry_run is True
    - All findings are structured dicts; raw evidence (redacted) goes in evidence list
    """

    technique_id: str  # ATT&CK ID, e.g. "T1046"
    tactic: str        # ATT&CK tactic, e.g. "discovery"
    name: str          # Human-readable name
    emulation_only: bool = True  # MUST remain True — no exploitation

    @abc.abstractmethod
    def execute(self, ctx: TechniqueContext) -> "TechniqueResult":
        """Execute the technique within the given context."""
        ...

    # ------------------------------------------------------------------
    # Safe-harbor helpers — call these before any network action
    # ------------------------------------------------------------------
    def _check_scope_ip(self, scope: Scope, ip: str) -> None:
        """Raise OutOfScopeError if ip is not in scope."""
        if not scope.allows_ip(ip):
            raise OutOfScopeError(f"{ip} is not in scope for technique {self.technique_id}")

    def _check_scope_domain(self, scope: Scope, domain: str) -> None:
        """Raise OutOfScopeError if domain is not in scope."""
        if not scope.allows_domain(domain):
            raise OutOfScopeError(
                f"{domain} is not in scope for technique {self.technique_id}"
            )

    def _check_scope_account(self, scope: Scope, upn: str) -> None:
        """Raise OutOfScopeError if account is not an authorised test account."""
        if not scope.allows_account(upn):
            raise OutOfScopeError(
                f"{upn} is not in target_accounts scope for technique {self.technique_id}. "
                "Only explicitly listed test accounts may be targeted."
            )

    # ------------------------------------------------------------------
    # Result factories — use these to ensure consistent TechniqueResult shape
    # ------------------------------------------------------------------
    def _make_result(
        self,
        ctx: TechniqueContext,
        status: "ResultStatus",
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]] | None = None,
        error: str | None = None,
    ) -> "TechniqueResult":
        from redgnat.orm.models import TechniqueResult

        return TechniqueResult(
            run_id=ctx.run_id,
            scenario_id=ctx.scenario_id,
            feed_id=ctx.feed_id,
            technique_id=self.technique_id,
            tactic=self.tactic,
            status=status,
            findings=findings,
            evidence=evidence or [],
            error=error,
        )

    def _dry_run_result(self, ctx: TechniqueContext, description: str) -> "TechniqueResult":
        from redgnat.orm.models import ResultStatus

        logger.info(
            "[DRY RUN] %s (%s): %s",
            self.technique_id,
            self.name,
            description,
        )
        return self._make_result(
            ctx,
            ResultStatus.DRY_RUN,
            findings=[{"dry_run": True, "would_have_done": description}],
        )

    def _blocked_result(
        self, ctx: TechniqueContext, reason: str
    ) -> "TechniqueResult":
        from redgnat.orm.models import ResultStatus

        logger.warning(
            "[BLOCKED] %s (%s): %s",
            self.technique_id,
            self.name,
            reason,
        )
        return self._make_result(
            ctx,
            ResultStatus.BLOCKED,
            findings=[{"blocked": True, "reason": reason}],
        )

    @staticmethod
    def _rate_sleep(scope: Scope, n_requests: int = 1) -> None:
        """Sleep to respect scope.max_rate_per_minute."""
        if scope.max_rate_per_minute > 0 and n_requests > 0:
            delay = (60.0 / scope.max_rate_per_minute) * n_requests
            time.sleep(min(delay, 5.0))
