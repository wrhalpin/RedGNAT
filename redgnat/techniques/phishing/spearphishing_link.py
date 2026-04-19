# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Spearphishing Link — T1566.002

Creates and manages a GoPhish link-based spearphishing campaign targeting
email addresses within the configured scope.

The campaign uses a redirect landing page that captures clicks and optionally
collects credentials. All campaign targets must belong to in-scope domains.

Emulation only: tracks user interaction metrics (click rate, credential
submission rate) without deploying actual malware payloads.
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

# Default link-based phishing template (credential harvest page)
_DEFAULT_EMAIL_TEMPLATE = {
    "name": "RedGNAT Link Template",
    "subject": "Action Required: Review Your Account",
    "html": (
        "<html><body>"
        "<p>Please review your account settings by clicking the link below:</p>"
        "<p><a href='{{.URL}}'>Review Account</a></p>"
        "<p>This link will expire in 24 hours.</p>"
        "</body></html>"
    ),
    "text": "Please review your account: {{.URL}}",
}

_DEFAULT_LANDING_PAGE = {
    "name": "RedGNAT Credential Capture",
    "html": (
        "<!DOCTYPE html><html><body>"
        "<h2>Sign In</h2>"
        "<form method='POST' action='{{.URL}}'>"
        "<label>Username: <input type='text' name='username' /></label><br>"
        "<label>Password: <input type='password' name='password' /></label><br>"
        "<input type='submit' value='Sign In'>"
        "</form>"
        "</body></html>"
    ),
    "capture_credentials": True,
    "capture_passwords": False,  # Only capture that creds were submitted, not the values
}


class SpearphishingLinkTechnique(Technique):
    """
    ATT&CK T1566.002 — Spearphishing Link.

    Launches a GoPhish link campaign against test-account email targets
    within in-scope domains.

    Parameters (ctx.params)
    -----------------------
    targets : list[dict]
        List of {"first_name": ..., "last_name": ..., "email": ..., "position": ...}.
        All email domains must be in scope.target_domains.
    campaign_name : str
        Optional campaign label (auto-generated if omitted).
    email_template : dict
        GoPhish template dict to use (uses default link template if omitted).
    landing_page : dict
        GoPhish landing page dict (uses default credential capture page if omitted).
    campaign_hours : int
        Duration in hours (default: from config).
    wait_minutes : int
        How many minutes to poll for results before returning (default: 5).
    """

    technique_id = "T1566.002"
    tactic = "initial-access"
    name = "Spearphishing Link Campaign"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        targets_raw: list[dict] = ctx.params.get("targets", [])

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would create GoPhish link campaign targeting {len(targets_raw)} accounts "
                f"in domains: {ctx.scope.target_domains}",
            )

        if not cfg.gophish_base_url or not cfg.gophish_api_key:
            return self._blocked_result(ctx, "GoPhish not configured (gophish.base_url / gophish.api_key)")

        # Validate all target email domains are in scope
        validated_targets = []
        for t in targets_raw:
            email = t.get("email", "")
            domain = email.split("@")[-1] if "@" in email else ""
            if not ctx.scope.allows_domain(domain):
                logger.warning("SpearphishingLink: skipping out-of-scope target %s", email)
                continue
            validated_targets.append(t)

        if not validated_targets:
            return self._blocked_result(ctx, "No in-scope targets provided for link campaign")

        client = GoPhishClient(cfg.gophish_base_url, cfg.gophish_api_key)
        campaign_name = ctx.params.get(
            "campaign_name", f"RedGNAT-Link-{ctx.run_id[:8]}-{uuid.uuid4().hex[:4]}"
        )
        campaign_hours = int(ctx.params.get("campaign_hours", cfg.gophish_default_campaign_hours))
        wait_minutes = int(ctx.params.get("wait_minutes", 5))

        created_resources: dict[str, int] = {}
        try:
            # Create target group
            group = client.create_group(name=f"{campaign_name}-targets", targets=validated_targets)
            created_resources["group_id"] = group["id"]

            # Create email template
            template_dict = dict(
                ctx.params.get("email_template", _DEFAULT_EMAIL_TEMPLATE)
            )
            template_dict["name"] = f"{campaign_name}-tmpl"
            template = client.create_template(template_dict)
            created_resources["template_id"] = template["id"]

            # Create landing page
            page_dict = dict(ctx.params.get("landing_page", _DEFAULT_LANDING_PAGE))
            page_dict["name"] = f"{campaign_name}-page"
            page = client.create_page(page_dict)
            created_resources["page_id"] = page["id"]

            # Validate sending profile exists
            smtp_profiles = client.list_smtp()
            if not smtp_profiles:
                raise RuntimeError("No GoPhish sending profiles configured")
            smtp_id = cfg.gophish_sending_profile_id

            # Create and launch campaign
            import datetime as dt
            now = dt.datetime.utcnow()
            launch_date = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")

            campaign_payload = {
                "name": campaign_name,
                "template": {"name": template_dict["name"]},
                "landing_page": {"name": page_dict["name"]},
                "url": cfg.gophish_landing_page_base_url or "https://click.example.com",
                "launch_date": launch_date,
                "send_by_date": "",
                "smtp": {"id": smtp_id},
                "groups": [{"name": f"{campaign_name}-targets"}],
            }
            campaign = client.create_campaign(campaign_payload)
            campaign_id = campaign["id"]
            created_resources["campaign_id"] = campaign_id

            logger.info(
                "SpearphishingLink: launched campaign %s (id=%d) targeting %d accounts [run=%s]",
                campaign_name,
                campaign_id,
                len(validated_targets),
                ctx.run_id,
            )

            # Poll for initial results
            time.sleep(wait_minutes * 60)
            results = client.get_campaign_summary(campaign_id)

            stats = results.get("stats", {})
            findings = [
                {
                    "campaign_id": campaign_id,
                    "campaign_name": campaign_name,
                    "total_targets": len(validated_targets),
                    "emails_sent": stats.get("sent", 0),
                    "emails_opened": stats.get("opened", 0),
                    "links_clicked": stats.get("clicked", 0),
                    "credentials_submitted": stats.get("submitted_data", 0),
                    "click_rate": (
                        stats.get("clicked", 0) / max(stats.get("sent", 1), 1)
                    ),
                }
            ]
            return self._make_result(ctx, ResultStatus.SUCCESS, findings)

        except Exception as exc:
            logger.exception("SpearphishingLink campaign failed: %s", exc)
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[{"created_resources": created_resources}],
                error=str(exc),
            )
