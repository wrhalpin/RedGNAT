# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Spearphishing Attachment — T1566.001

Creates a GoPhish attachment-based spearphishing campaign.

The attachment is a benign document (PDF or DOCX) that contains a tracking
pixel or macro beacon — no actual malicious payload. The technique measures
open rate, attachment-open rate, and macro-enable rate to assess user
susceptibility and email gateway effectiveness.

Emulation only: attachments contain no executable payload — only a harmless
web-beacon image tag that phones home to the GoPhish landing page.
"""
from __future__ import annotations

import base64
import logging
import time
import uuid
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext
from redgnat.techniques.phishing.base import GoPhishClient

logger = logging.getLogger(__name__)

# Minimal 1x1 pixel PNG as base64 (used as the tracking beacon image)
_PIXEL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDQADHQL/Ar4XZgAAAABJRU5ErkJggg=="
)

_ATTACHMENT_EMAIL_TEMPLATE = {
    "name": "RedGNAT Attachment Template",
    "subject": "Please review the attached document",
    "html": (
        "<html><body>"
        "<p>Hi {{.FirstName}},</p>"
        "<p>Please find attached a document that requires your immediate review.</p>"
        "<p>If you have any questions, reply to this email.</p>"
        "</body></html>"
    ),
    "text": "Please review the attached document.",
    "attachments": [],  # populated at runtime
}

# Minimal HTML file masquerading as a document (tracking pixel inside)
_BEACON_HTML = (
    "<!DOCTYPE html><html><head><title>Document</title></head><body>"
    "<p>Loading document...</p>"
    "<img src='{{.URL}}?rid={{.RId}}' width='1' height='1' style='display:none'>"
    "</body></html>"
)


class SpearphishingAttachmentTechnique(Technique):
    """
    ATT&CK T1566.001 — Spearphishing Attachment.

    Sends a benign-but-trackable attachment to in-scope targets via GoPhish.
    Measures attachment-open rate (via beacon ping to GoPhish landing page).

    Parameters (ctx.params)
    -----------------------
    targets : list[dict]
        Email target list. All email domains must be in scope.
    attachment_name : str
        Filename for the attachment (default: "Q4_Report.html").
    campaign_name : str
        Optional campaign label.
    wait_minutes : int
        How long to wait before pulling results (default: 10).
    """

    technique_id = "T1566.001"
    tactic = "initial-access"
    name = "Spearphishing Attachment Campaign"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        targets_raw: list[dict] = ctx.params.get("targets", [])
        attachment_name = ctx.params.get("attachment_name", "Q4_Report.html")
        wait_minutes = int(ctx.params.get("wait_minutes", 10))

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would send attachment '{attachment_name}' to {len(targets_raw)} targets",
            )

        if not cfg.gophish_base_url or not cfg.gophish_api_key:
            return self._blocked_result(ctx, "GoPhish not configured")

        # Scope-check all targets
        validated_targets = []
        for t in targets_raw:
            email = t.get("email", "")
            domain = email.split("@")[-1] if "@" in email else ""
            if ctx.scope.allows_domain(domain):
                validated_targets.append(t)
            else:
                logger.warning("SpearphishingAttachment: skipping out-of-scope %s", email)

        if not validated_targets:
            return self._blocked_result(ctx, "No in-scope targets provided")

        client = GoPhishClient(cfg.gophish_base_url, cfg.gophish_api_key)
        campaign_name = ctx.params.get(
            "campaign_name", f"RedGNAT-Attach-{ctx.run_id[:8]}-{uuid.uuid4().hex[:4]}"
        )

        created_resources: dict[str, int] = {}
        try:
            # Build beacon HTML attachment (harmless — tracking pixel only)
            beacon_content = _BEACON_HTML.replace(
                "{{.URL}}", cfg.gophish_landing_page_base_url or "https://click.example.com"
            )
            attachment_b64 = base64.b64encode(beacon_content.encode()).decode()

            template_dict = dict(_ATTACHMENT_EMAIL_TEMPLATE)
            template_dict["name"] = f"{campaign_name}-tmpl"
            template_dict["attachments"] = [
                {
                    "content": attachment_b64,
                    "type": "text/html",
                    "name": attachment_name,
                }
            ]

            template = client.create_template(template_dict)
            created_resources["template_id"] = template["id"]

            # Simple tracking landing page
            page_dict = {
                "name": f"{campaign_name}-page",
                "html": "<html><body><p>Thank you for your interest.</p></body></html>",
                "capture_credentials": False,
                "capture_passwords": False,
            }
            page = client.create_page(page_dict)
            created_resources["page_id"] = page["id"]

            group = client.create_group(
                name=f"{campaign_name}-targets", targets=validated_targets
            )
            created_resources["group_id"] = group["id"]

            smtp_profiles = client.list_smtp()
            if not smtp_profiles:
                raise RuntimeError("No GoPhish sending profiles")

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
                "SpearphishingAttachment: launched campaign %s (id=%d) targeting %d [run=%s]",
                campaign_name,
                campaign_id,
                len(validated_targets),
                ctx.run_id,
            )

            time.sleep(wait_minutes * 60)
            results = client.get_campaign_summary(campaign_id)
            stats = results.get("stats", {})

            findings = [
                {
                    "campaign_id": campaign_id,
                    "campaign_name": campaign_name,
                    "attachment_name": attachment_name,
                    "total_targets": len(validated_targets),
                    "emails_sent": stats.get("sent", 0),
                    "emails_opened": stats.get("opened", 0),
                    "attachments_opened": stats.get("clicked", 0),  # beacon ping = opened
                    "open_rate": stats.get("clicked", 0) / max(stats.get("sent", 1), 1),
                }
            ]
            return self._make_result(ctx, ResultStatus.SUCCESS, findings)

        except Exception as exc:
            logger.exception("SpearphishingAttachment campaign failed: %s", exc)
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[{"created_resources": created_resources}],
                error=str(exc),
            )
