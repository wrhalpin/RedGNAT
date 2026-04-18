"""
GoPhish API client — shared base for all phishing technique modules.

GoPhish (https://getgophish.com) is the backend for RedGNAT phishing campaigns.
This module wraps the GoPhish REST API (v2) using urllib3 / stdlib urllib.

Emulation-only: campaigns are real phishing simulations scoped to target_domains
configured in the safe-harbor scope. No actual malware is delivered.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
import ssl
from typing import Any

logger = logging.getLogger(__name__)


class GoPhishClient:
    """
    Thin GoPhish REST API v2 client.

    Parameters
    ----------
    base_url : str
        GoPhish API base URL including port, e.g. https://gophish.example.com:3333
    api_key : str
        GoPhish API key.
    verify_ssl : bool
        Whether to verify the GoPhish TLS certificate (default False for self-signed).
    """

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = False) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._ssl_ctx = ssl.create_default_context() if verify_ssl else self._no_verify_ctx()

    @staticmethod
    def _no_verify_ctx() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read())

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------
    def create_campaign(self, payload: dict) -> dict:
        return self._request("POST", "/api/campaigns/", body=payload)

    def get_campaign(self, campaign_id: int) -> dict:
        return self._request("GET", f"/api/campaigns/{campaign_id}")

    def list_campaigns(self) -> list[dict]:
        return self._request("GET", "/api/campaigns/") or []

    def complete_campaign(self, campaign_id: int) -> dict:
        return self._request("DELETE", f"/api/campaigns/{campaign_id}")

    def get_campaign_results(self, campaign_id: int) -> dict:
        return self._request("GET", f"/api/campaigns/{campaign_id}/results")

    def get_campaign_summary(self, campaign_id: int) -> dict:
        return self._request("GET", f"/api/campaigns/{campaign_id}/summary")

    # ------------------------------------------------------------------
    # Groups (target lists)
    # ------------------------------------------------------------------
    def create_group(self, name: str, targets: list[dict]) -> dict:
        return self._request("POST", "/api/groups/", body={"name": name, "targets": targets})

    def get_group(self, group_id: int) -> dict:
        return self._request("GET", f"/api/groups/{group_id}")

    def delete_group(self, group_id: int) -> None:
        self._request("DELETE", f"/api/groups/{group_id}")

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------
    def create_template(self, template: dict) -> dict:
        return self._request("POST", "/api/templates/", body=template)

    def list_templates(self) -> list[dict]:
        return self._request("GET", "/api/templates/") or []

    def delete_template(self, template_id: int) -> None:
        self._request("DELETE", f"/api/templates/{template_id}")

    # ------------------------------------------------------------------
    # Landing pages
    # ------------------------------------------------------------------
    def create_page(self, page: dict) -> dict:
        return self._request("POST", "/api/pages/", body=page)

    def list_pages(self) -> list[dict]:
        return self._request("GET", "/api/pages/") or []

    def delete_page(self, page_id: int) -> None:
        self._request("DELETE", f"/api/pages/{page_id}")

    # ------------------------------------------------------------------
    # Sending profiles
    # ------------------------------------------------------------------
    def list_smtp(self) -> list[dict]:
        return self._request("GET", "/api/smtp/") or []
