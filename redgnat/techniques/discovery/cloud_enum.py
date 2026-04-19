# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Cloud Identity & Resource Enumeration — T1087.004, T1069.003, T1526

Read-only enumeration of cloud identity providers and resources:
- Microsoft Entra ID (Azure AD): users, groups, applications, service principals
- Okta: users, groups, applications
- AWS IAM: users, groups, roles, policies

Emulation only: uses read-only API permissions; never modifies cloud resources.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]


class CloudEnumTechnique(Technique):
    """
    ATT&CK T1087.004 / T1069.003 / T1526 — Cloud Identity Enumeration.

    Enumerates cloud identity objects across Entra ID, Okta, and AWS IAM.
    Results expose potential credential attack targets and privilege escalation paths.

    Parameters (ctx.params)
    -----------------------
    providers : list[str]
        Which providers to query: ["entra", "okta", "aws"] (default: all configured).
    max_users : int
        Maximum users to retrieve per provider (default: 200).
    max_groups : int
        Maximum groups to retrieve per provider (default: 100).
    """

    technique_id = "T1087.004"
    tactic = "discovery"
    name = "Cloud Account & Service Discovery"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx, "Would enumerate Entra ID / Okta / AWS IAM users, groups, and applications"
            )

        from redgnat.config import RedGNATConfig
        cfg = RedGNATConfig()

        providers = ctx.params.get("providers", ["entra", "okta", "aws"])
        max_users = int(ctx.params.get("max_users", 200))
        max_groups = int(ctx.params.get("max_groups", 100))

        findings: list[dict] = []
        evidence: list[dict] = []
        errors: list[str] = []

        if "entra" in providers and cfg.entra_tenant_id:
            try:
                entra_findings = self._enum_entra(cfg, max_users, max_groups)
                findings.extend(entra_findings)
            except Exception as exc:
                logger.warning("Entra enumeration failed: %s", exc)
                errors.append(f"entra: {exc}")

        if "okta" in providers and cfg.okta_base_url:
            try:
                okta_findings = self._enum_okta(cfg, max_users, max_groups)
                findings.extend(okta_findings)
            except Exception as exc:
                logger.warning("Okta enumeration failed: %s", exc)
                errors.append(f"okta: {exc}")

        if "aws" in providers and cfg.aws_access_key_id:
            try:
                aws_findings = self._enum_aws(cfg, max_users, max_groups)
                findings.extend(aws_findings)
            except Exception as exc:
                logger.warning("AWS enumeration failed: %s", exc)
                errors.append(f"aws: {exc}")

        if not findings and not errors:
            return self._blocked_result(
                ctx, "No cloud providers configured (entra_tenant_id / okta_base_url / aws_access_key_id)"
            )

        status = ResultStatus.SUCCESS if findings else ResultStatus.ERROR
        return self._make_result(
            ctx,
            status,
            findings,
            evidence,
            error="; ".join(errors) if errors else None,
        )

    # ------------------------------------------------------------------
    # Entra ID (Microsoft Graph API)
    # ------------------------------------------------------------------
    def _enum_entra(self, cfg: Any, max_users: int, max_groups: int) -> list[dict]:
        token = self._get_entra_token(cfg)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        results: list[dict] = [{"provider": "entra"}]

        # Users
        users = self._graph_get(
            f"{_GRAPH_BASE}/users?$top={min(max_users, 999)}"
            "&$select=id,displayName,userPrincipalName,accountEnabled,"
            "createdDateTime,lastSignInDateTime,assignedLicenses",
            headers,
        )
        results.append({
            "category": "entra_users",
            "count": len(users),
            "sample": [
                {
                    "upn": u.get("userPrincipalName"),
                    "display_name": u.get("displayName"),
                    "enabled": u.get("accountEnabled"),
                    "last_signin": u.get("lastSignInDateTime"),
                }
                for u in users[:20]
            ],
        })
        logger.info("CloudEnum: found %d Entra users", len(users))

        # Groups
        groups = self._graph_get(
            f"{_GRAPH_BASE}/groups?$top={min(max_groups, 999)}"
            "&$select=id,displayName,securityEnabled,isAssignableToRole,createdDateTime",
            headers,
        )
        results.append({"category": "entra_groups", "count": len(groups)})

        # Applications (OAuth attack surface)
        apps = self._graph_get(
            f"{_GRAPH_BASE}/applications?$top=100&$select=id,displayName,appId,requiredResourceAccess",
            headers,
        )
        results.append({"category": "entra_applications", "count": len(apps), "apps": [
            {"name": a.get("displayName"), "app_id": a.get("appId")} for a in apps[:20]
        ]})

        # Service principals (enterprise apps)
        sps = self._graph_get(
            f"{_GRAPH_BASE}/servicePrincipals?$top=100&$select=id,displayName,appId,enabled",
            headers,
        )
        results.append({"category": "entra_service_principals", "count": len(sps)})

        return results

    def _get_entra_token(self, cfg: Any) -> str:
        url = f"{cfg.entra_authority}/{cfg.entra_tenant_id}/oauth2/v2.0/token"
        data = urllib.parse.urlencode({
            "client_id": cfg.entra_client_id,
            "client_secret": cfg.entra_client_secret,
            "scope": " ".join(_GRAPH_SCOPES),
            "grant_type": "client_credentials",
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            body = json.loads(resp.read())
        return body["access_token"]

    def _graph_get(self, url: str, headers: dict) -> list[dict]:
        """Paginate through Microsoft Graph API, returning all items."""
        items: list[dict] = []
        while url:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                body = json.loads(resp.read())
            items.extend(body.get("value", []))
            url = body.get("@odata.nextLink", "")
        return items

    # ------------------------------------------------------------------
    # Okta
    # ------------------------------------------------------------------
    def _enum_okta(self, cfg: Any, max_users: int, max_groups: int) -> list[dict]:
        base = cfg.okta_base_url.rstrip("/")
        token = cfg.okta_api_token
        headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}

        results: list[dict] = [{"provider": "okta"}]

        # Users
        users = self._okta_get(
            f"{base}/api/v1/users?limit={min(max_users, 200)}&filter=status+eq+%22ACTIVE%22",
            headers,
        )
        results.append({
            "category": "okta_users",
            "count": len(users),
            "sample": [
                {
                    "login": u.get("profile", {}).get("login"),
                    "display_name": u.get("profile", {}).get("displayName"),
                    "status": u.get("status"),
                    "last_login": u.get("lastLogin"),
                }
                for u in users[:20]
            ],
        })
        logger.info("CloudEnum: found %d active Okta users", len(users))

        # Groups
        groups = self._okta_get(
            f"{base}/api/v1/groups?limit={min(max_groups, 200)}", headers
        )
        results.append({"category": "okta_groups", "count": len(groups)})

        # Applications
        apps = self._okta_get(f"{base}/api/v1/apps?limit=100", headers)
        results.append({"category": "okta_apps", "count": len(apps), "apps": [
            {"label": a.get("label"), "status": a.get("status")} for a in apps[:20]
        ]})

        return results

    def _okta_get(self, url: str, headers: dict) -> list[dict]:
        items: list[dict] = []
        while url:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                body = json.loads(resp.read())
                link_header = resp.headers.get("Link", "")
            items.extend(body if isinstance(body, list) else [body])
            # Parse next-page from Link header
            url = self._parse_link_next(link_header)
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

    # ------------------------------------------------------------------
    # AWS IAM
    # ------------------------------------------------------------------
    def _enum_aws(self, cfg: Any, max_users: int, max_groups: int) -> list[dict]:
        try:
            import boto3  # type: ignore[import]
        except ImportError:
            raise RuntimeError("boto3 not installed — pip install boto3")

        session_kwargs: dict[str, Any] = {
            "aws_access_key_id": cfg.aws_access_key_id,
            "aws_secret_access_key": cfg.aws_secret_access_key,
            "region_name": cfg.aws_default_region,
        }
        session = boto3.Session(**session_kwargs)

        if cfg.aws_assume_role_arn:
            sts = session.client("sts")
            creds = sts.assume_role(
                RoleArn=cfg.aws_assume_role_arn, RoleSessionName="redgnat-enum"
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=cfg.aws_default_region,
            )

        iam = session.client("iam")
        results: list[dict] = [{"provider": "aws"}]

        # IAM users
        users_resp = iam.list_users(MaxItems=min(max_users, 1000))
        users = users_resp.get("Users", [])
        results.append({
            "category": "aws_iam_users",
            "count": len(users),
            "sample": [
                {
                    "username": u.get("UserName"),
                    "arn": u.get("Arn"),
                    "created": str(u.get("CreateDate", "")),
                    "password_last_used": str(u.get("PasswordLastUsed", "never")),
                }
                for u in users[:20]
            ],
        })
        logger.info("CloudEnum: found %d AWS IAM users", len(users))

        # IAM groups
        groups_resp = iam.list_groups(MaxItems=min(max_groups, 1000))
        results.append({"category": "aws_iam_groups", "count": len(groups_resp.get("Groups", []))})

        # IAM roles
        roles_resp = iam.list_roles(MaxItems=100)
        results.append({"category": "aws_iam_roles", "count": len(roles_resp.get("Roles", []))})

        # Account summary (password policy, MFA, etc.)
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            results.append({"category": "aws_account_summary", "summary": summary})
        except Exception:
            pass

        return results
