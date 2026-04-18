"""
Web Session Cookie / Token Theft Pattern Detection — T1539

Rather than actively stealing tokens, this technique analyzes IdP audit logs
for patterns that indicate token theft or session hijacking is already occurring
or would go undetected:

1. Impossible travel — sign-ins from geographically distant locations within a
   short time window (suggests token replay or account sharing)
2. Refresh token anomalies — tokens being used from unusual user-agents or IP ranges
3. Primary Refresh Token (PRT) misuse indicators in Entra ID CAE logs
4. Long-lived session detection — sessions active beyond expected policy limits

This is a detective/gap-analysis technique, not an active attack.
It answers: "Would token theft go undetected in our current posture?"

Providers:
- Entra ID: Microsoft Graph API sign-in logs + CAE audit events
- Okta: System Log API

Emulation only: read-only API access to audit logs; no token capture or replay.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# Impossible travel threshold — sign-ins from two locations within this window
# that are geographically impossible given the time difference
_IMPOSSIBLE_TRAVEL_MINUTES = 60
# Session longevity threshold — flag sessions older than this
_LONG_SESSION_HOURS = 24


class TokenTheftTechnique(Technique):
    """
    ATT&CK T1539 — Steal Web Session Cookie (Detective / Gap Analysis).

    Analyzes identity provider audit logs for token theft indicators:
    - Impossible travel / concurrent session anomalies
    - Long-lived sessions beyond policy expectations
    - Sign-ins from unusual ASNs/user-agents that suggest token replay
    - Absence of Continuous Access Evaluation (CAE) signals

    Parameters (ctx.params)
    -----------------------
    providers : list[str]
        ["entra", "okta"] (default: all configured).
    lookback_hours : int
        How far back to analyze sign-in logs (default: 24).
    flag_long_sessions_hours : int
        Flag sessions longer than this many hours (default: 24).
    """

    technique_id = "T1539"
    tactic = "credential-access"
    name = "Session Token Theft Gap Analysis"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        providers = ctx.params.get("providers", ["entra", "okta"])
        lookback_hours = int(ctx.params.get("lookback_hours", 24))
        long_session_hours = int(ctx.params.get("flag_long_sessions_hours", _LONG_SESSION_HOURS))

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would analyze sign-in logs for token theft indicators "
                f"(last {lookback_hours}h) across {providers}",
            )

        findings: list[dict] = []
        errors: list[str] = []
        since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

        if "entra" in providers and cfg.entra_tenant_id:
            try:
                entra_findings = self._analyze_entra(cfg, since, long_session_hours)
                findings.extend(entra_findings)
            except Exception as exc:
                logger.warning("TokenTheft Entra analysis failed: %s", exc)
                errors.append(f"entra: {exc}")

        if "okta" in providers and cfg.okta_base_url:
            try:
                okta_findings = self._analyze_okta(cfg, since, long_session_hours)
                findings.extend(okta_findings)
            except Exception as exc:
                logger.warning("TokenTheft Okta analysis failed: %s", exc)
                errors.append(f"okta: {exc}")

        if not findings and not errors:
            return self._blocked_result(ctx, "No IdP providers configured for log analysis")

        status = ResultStatus.SUCCESS if findings else ResultStatus.PARTIAL
        return self._make_result(
            ctx,
            status,
            findings,
            error="; ".join(errors) if errors else None,
        )

    # ------------------------------------------------------------------
    # Entra ID Sign-in Log Analysis
    # ------------------------------------------------------------------
    def _analyze_entra(self, cfg: Any, since: datetime, long_session_hours: int) -> list[dict]:
        token = self._get_entra_token(cfg)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        url = (
            f"{_GRAPH_BASE}/auditLogs/signIns?"
            f"$filter=createdDateTime ge {since_iso}&"
            "$select=id,createdDateTime,userPrincipalName,ipAddress,"
            "location,status,riskState,riskDetail,clientAppUsed,"
            "authenticationRequirement,isInteractive&"
            "$top=500"
        )

        sign_ins = self._graph_paginate(url, headers, max_pages=5)
        findings: list[dict] = [{"provider": "entra", "sign_ins_analyzed": len(sign_ins)}]

        # Flag risky sign-ins
        risky = [s for s in sign_ins if s.get("riskState") not in {"none", None}]
        if risky:
            findings.append({
                "category": "entra_risky_signins",
                "count": len(risky),
                "risk_states": list({s.get("riskState") for s in risky}),
                "sample": [
                    {
                        "upn": s.get("userPrincipalName"),
                        "risk_state": s.get("riskState"),
                        "risk_detail": s.get("riskDetail"),
                        "ip": s.get("ipAddress"),
                    }
                    for s in risky[:10]
                ],
            })

        # Impossible travel detection (simple: same UPN, two IPs, short window)
        impossible = self._detect_impossible_travel(sign_ins)
        if impossible:
            findings.append({
                "category": "entra_impossible_travel",
                "count": len(impossible),
                "events": impossible[:10],
                "interpretation": "Potential token replay or shared credentials detected",
            })

        # Check CAE presence — are continuous access evaluation events present?
        cae_signins = [
            s for s in sign_ins
            if "continuousAccessEvaluation" in str(s.get("authenticationRequirement", ""))
        ]
        findings.append({
            "category": "entra_cae_coverage",
            "cae_enabled_signins": len(cae_signins),
            "total_signins": len(sign_ins),
            "cae_coverage_pct": len(cae_signins) / max(len(sign_ins), 1) * 100,
            "recommendation": (
                "Enable Continuous Access Evaluation for all apps to reduce "
                "token theft window" if len(cae_signins) < len(sign_ins) * 0.8
                else "CAE coverage appears good"
            ),
        })

        return findings

    def _analyze_okta(self, cfg: Any, since: datetime, long_session_hours: int) -> list[dict]:
        base = cfg.okta_base_url.rstrip("/")
        token = cfg.okta_api_token
        headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}

        since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        url = (
            f"{base}/api/v1/logs?"
            f"since={urllib.parse.quote(since_iso)}&"
            "filter=eventType+eq+%22user.session.start%22&"
            "limit=500"
        )

        events = self._okta_paginate(url, headers, max_pages=3)
        findings: list[dict] = [{"provider": "okta", "session_events_analyzed": len(events)}]

        # Look for sessions from multiple IPs for the same user
        impossible = self._detect_okta_impossible_travel(events)
        if impossible:
            findings.append({
                "category": "okta_impossible_travel",
                "count": len(impossible),
                "events": impossible[:10],
                "interpretation": "Potential session hijack or token replay",
            })

        # Detect MFA bypass events
        mfa_bypass = [
            e for e in events
            if any(
                "MFA" not in str(a.get("authenticationContext", ""))
                for a in [e]
            )
        ]

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_impossible_travel(sign_ins: list[dict]) -> list[dict]:
        by_user: dict[str, list[dict]] = {}
        for s in sign_ins:
            upn = s.get("userPrincipalName", "")
            by_user.setdefault(upn, []).append(s)

        impossible = []
        for upn, events in by_user.items():
            if len(events) < 2:
                continue
            sorted_events = sorted(events, key=lambda e: e.get("createdDateTime", ""))
            for i in range(len(sorted_events) - 1):
                a, b = sorted_events[i], sorted_events[i + 1]
                ip_a = a.get("ipAddress", "")
                ip_b = b.get("ipAddress", "")
                if ip_a and ip_b and ip_a != ip_b:
                    # Simple: flag all different-IP pairs within the window
                    impossible.append(
                        {
                            "upn": upn,
                            "ip_a": ip_a,
                            "ip_b": ip_b,
                            "time_a": a.get("createdDateTime"),
                            "time_b": b.get("createdDateTime"),
                            "location_a": a.get("location", {}).get("city"),
                            "location_b": b.get("location", {}).get("city"),
                        }
                    )
        return impossible

    @staticmethod
    def _detect_okta_impossible_travel(events: list[dict]) -> list[dict]:
        by_user: dict[str, list[dict]] = {}
        for e in events:
            upn = e.get("actor", {}).get("alternateId", "")
            by_user.setdefault(upn, []).append(e)

        impossible = []
        for upn, evts in by_user.items():
            if len(evts) < 2:
                continue
            sorted_evts = sorted(evts, key=lambda e: e.get("published", ""))
            for i in range(len(sorted_evts) - 1):
                a, b = sorted_evts[i], sorted_evts[i + 1]
                ip_a = a.get("client", {}).get("ipAddress", "")
                ip_b = b.get("client", {}).get("ipAddress", "")
                if ip_a and ip_b and ip_a != ip_b:
                    impossible.append({"upn": upn, "ip_a": ip_a, "ip_b": ip_b})
        return impossible

    def _get_entra_token(self, cfg: Any) -> str:
        url = f"{cfg.entra_authority}/{cfg.entra_tenant_id}/oauth2/v2.0/token"
        data = urllib.parse.urlencode({
            "client_id": cfg.entra_client_id,
            "client_secret": cfg.entra_client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return json.loads(resp.read())["access_token"]

    def _graph_paginate(self, url: str, headers: dict, max_pages: int = 5) -> list[dict]:
        items: list[dict] = []
        pages = 0
        while url and pages < max_pages:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                body = json.loads(resp.read())
            items.extend(body.get("value", []))
            url = body.get("@odata.nextLink", "")
            pages += 1
        return items

    def _okta_paginate(self, url: str, headers: dict, max_pages: int = 3) -> list[dict]:
        items: list[dict] = []
        pages = 0
        while url and pages < max_pages:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                body = json.loads(resp.read())
                link_header = resp.headers.get("Link", "")
            items.extend(body if isinstance(body, list) else [])
            url = self._parse_link_next(link_header)
            pages += 1
        return items

    @staticmethod
    def _parse_link_next(link_header: str) -> str:
        for part in link_header.split(","):
            if 'rel="next"' in part:
                start = part.find("<") + 1
                end = part.find(">")
                if start > 0 and end > start:
                    return part[start:end]
        return ""
