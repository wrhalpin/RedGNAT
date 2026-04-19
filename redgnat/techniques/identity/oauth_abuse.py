# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
OAuth Application Consent Phishing — T1528

Simulates an OAuth consent phishing attack via a GoPhish campaign.

The landing page presents a fake OAuth application requesting broad permissions
(e.g. "Read all mail", "Read all files"). When a test user clicks "Accept",
GoPhish records the event — demonstrating that consent phishing would succeed
against users who lack training or whose tenant lacks app consent controls.

Emulation only:
- The "OAuth app" is a GoPhish landing page — no real OAuth app is registered
  on the target tenant (unless explicitly configured)
- No actual tokens are captured or used
- The technique measures user susceptibility and tenant consent controls

For a more realistic test, configure a real low-privilege app in Entra and
provide its OAuth consent URL via ctx.params["consent_url"].
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext
from redgnat.techniques.phishing.base import GoPhishClient

logger = logging.getLogger(__name__)

_CONSENT_PHISHING_EMAIL = {
    "name": "RedGNAT OAuth Consent Template",
    "subject": "New App Requires Your Authorization",
    "html": (
        "<html><body>"
        "<p>Hi {{.FirstName}},</p>"
        "<p>The app <strong>IT Security Tools</strong> requires your authorization "
        "to access your account. Please click the link below to grant access:</p>"
        "<p><a href='{{.URL}}'>Authorize IT Security Tools</a></p>"
        "<p>This is required for the upcoming security compliance audit.</p>"
        "</body></html>"
    ),
    "text": "Authorize IT Security Tools: {{.URL}}",
}

_CONSENT_PAGE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Grant Access</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #f0f0f0; }
  .card { max-width: 400px; margin: 80px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
  .app-icon { width: 48px; height: 48px; background: #0067b8; border-radius: 8px; margin: 0 auto 16px; display: flex; align-items: center; justify-content: center; color: white; font-size: 24px; }
  .permissions { background: #f9f9f9; border: 1px solid #e0e0e0; border-radius: 4px; padding: 12px; margin: 16px 0; }
  .permission { padding: 6px 0; border-bottom: 1px solid #eee; font-size: 14px; }
  .btn-accept { background: #0067b8; color: white; border: none; padding: 12px 24px; width: 100%; border-radius: 4px; cursor: pointer; font-size: 16px; }
  .btn-cancel { background: white; color: #666; border: 1px solid #ccc; padding: 12px 24px; width: 100%; border-radius: 4px; cursor: pointer; margin-top: 8px; }
</style>
</head>
<body>
<div class='card'>
  <div style='text-align:center'>
    <div class='app-icon'>🔒</div>
    <h2>IT Security Tools</h2>
    <p style='color:#666'>wants to access your account</p>
  </div>
  <div class='permissions'>
    <div class='permission'>✓ Read your email messages</div>
    <div class='permission'>✓ Read your files and documents</div>
    <div class='permission'>✓ Access your profile and contacts</div>
  </div>
  <form method='POST' action='{{.URL}}'>
    <input type='hidden' name='action' value='accept'>
    <button class='btn-accept' type='submit'>Accept</button>
  </form>
  <form method='GET' action='{{.URL}}'>
    <input type='hidden' name='action' value='cancel'>
    <button class='btn-cancel' type='button'>Cancel</button>
  </form>
</div>
</body>
</html>
"""


class OAuthAbuseTechnique(Technique):
    """
    ATT&CK T1528 — Steal Application Access Token (OAuth Consent Phishing).

    Sends a GoPhish campaign simulating an OAuth consent phishing attack.
    Measures how many test users would grant consent to a malicious application.

    Parameters (ctx.params)
    -----------------------
    targets : list[dict]
        Email target list. All domains must be in scope.
    consent_url : str | None
        If provided, redirect link-click directly to a real OAuth consent URL
        (for higher-fidelity testing with an actual registered app).
    campaign_name : str
        Optional label.
    wait_minutes : int
        Result poll wait (default: 15).
    """

    technique_id = "T1528"
    tactic = "credential-access"
    name = "OAuth Application Consent Phishing"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        targets_raw: list[dict] = ctx.params.get("targets", [])
        wait_minutes = int(ctx.params.get("wait_minutes", 15))
        real_consent_url: str | None = ctx.params.get("consent_url")

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would send OAuth consent phishing campaign to {len(targets_raw)} targets",
            )

        if not cfg.gophish_base_url or not cfg.gophish_api_key:
            return self._blocked_result(ctx, "GoPhish not configured")

        validated_targets = [
            t for t in targets_raw
            if ctx.scope.allows_domain((t.get("email", "").split("@") + [""])[-1])
        ]
        if not validated_targets:
            return self._blocked_result(ctx, "No in-scope targets")

        client = GoPhishClient(cfg.gophish_base_url, cfg.gophish_api_key)
        campaign_name = ctx.params.get(
            "campaign_name", f"RedGNAT-OAuth-{ctx.run_id[:8]}-{uuid.uuid4().hex[:4]}"
        )

        created_resources: dict[str, int] = {}
        try:
            template_dict = dict(_CONSENT_PHISHING_EMAIL)
            template_dict["name"] = f"{campaign_name}-tmpl"
            template = client.create_template(template_dict)
            created_resources["template_id"] = template["id"]

            page_dict = {
                "name": f"{campaign_name}-page",
                "html": _CONSENT_PAGE_HTML,
                "capture_credentials": True,
                "capture_passwords": False,
                "redirect_url": real_consent_url or "",
            }
            page = client.create_page(page_dict)
            created_resources["page_id"] = page["id"]

            group = client.create_group(
                name=f"{campaign_name}-targets", targets=validated_targets
            )
            created_resources["group_id"] = group["id"]

            import datetime as dt
            launch_date = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")

            campaign = client.create_campaign(
                {
                    "name": campaign_name,
                    "template": {"name": template_dict["name"]},
                    "landing_page": {"name": page_dict["name"]},
                    "url": cfg.gophish_landing_page_base_url or "https://click.example.com",
                    "launch_date": launch_date,
                    "smtp": {"id": cfg.gophish_sending_profile_id},
                    "groups": [{"name": f"{campaign_name}-targets"}],
                }
            )
            campaign_id = campaign["id"]
            created_resources["campaign_id"] = campaign_id

            logger.info(
                "OAuthAbuse: launched consent phishing campaign %s (id=%d) "
                "targeting %d [run=%s]",
                campaign_name,
                campaign_id,
                len(validated_targets),
                ctx.run_id,
            )

            time.sleep(wait_minutes * 60)
            results = client.get_campaign_summary(campaign_id)
            stats = results.get("stats", {})
            sent = max(stats.get("sent", 1), 1)
            consented = stats.get("submitted_data", 0)

            findings = [
                {
                    "campaign_id": campaign_id,
                    "campaign_name": campaign_name,
                    "attack_type": "oauth_consent_phishing",
                    "total_targets": len(validated_targets),
                    "emails_sent": stats.get("sent", 0),
                    "page_visits": stats.get("clicked", 0),
                    "consents_granted": consented,
                    "consent_rate": consented / sent,
                    "real_consent_url_used": real_consent_url is not None,
                    "recommendation": (
                        "Restrict OAuth app consent to admins only "
                        "(Entra: User consent settings → Restrict user consent)"
                        if consented > 0
                        else "Consent controls appear effective for this population"
                    ),
                }
            ]
            return self._make_result(ctx, ResultStatus.SUCCESS, findings)

        except Exception as exc:
            logger.exception("OAuthAbuse campaign failed: %s", exc)
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[{"created_resources": created_resources}],
                error=str(exc),
            )
