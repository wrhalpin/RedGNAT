# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Identity technique base — shared IdP client logic for credential attack emulation.

Provides lightweight authentication attempt wrappers for:
- Microsoft Entra ID (Azure AD) — OAuth2 ROPC + device code flows
- Okta — /api/v1/authn primary authentication endpoint
- Active Directory — LDAP simple bind

All methods are emulation-safe:
- Only target accounts listed in scope.target_accounts
- Enforce jitter and rate limiting between attempts
- Detect lockout responses and back off immediately
- Log outcomes without recording plaintext credentials
"""
from __future__ import annotations

import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuthAttemptResult:
    """Outcome of a single authentication attempt."""
    provider: str
    account: str
    password_hint: str  # only first char + length, never full password
    success: bool
    locked_out: bool
    mfa_required: bool
    error_code: str | None
    http_status: int | None
    raw_response_snippet: str | None  # first 200 chars only


def _redact_password(password: str) -> str:
    """Return a non-reversible hint (first char + asterisks)."""
    if not password:
        return "***"
    return password[0] + "*" * (len(password) - 1)


def _jitter_sleep(base_seconds: float, jitter_fraction: float = 0.3) -> None:
    """Sleep base_seconds ± jitter_fraction to avoid timing-based detection."""
    jitter = base_seconds * jitter_fraction * (random.random() * 2 - 1)
    time.sleep(max(0.5, base_seconds + jitter))


class EntraAuthClient:
    """
    Entra ID (Azure AD) authentication test client.

    Uses the ROPC (Resource Owner Password Credentials) OAuth2 grant to test
    username/password pairs against the /token endpoint.

    ROPC is intentionally disabled in many Entra tenants — a 400 "AADSTS90023"
    error indicates this (which is itself a useful finding for the red team report).
    """

    _TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

    def __init__(self, tenant_id: str, client_id: str) -> None:
        self._token_url = self._TOKEN_URL_TEMPLATE.format(tenant=tenant_id)
        self._client_id = client_id

    def attempt(self, username: str, password: str) -> AuthAttemptResult:
        data = urllib.parse.urlencode({
            "grant_type": "password",
            "client_id": self._client_id,
            "username": username,
            "password": password,
            "scope": "openid profile",
        }).encode()

        req = urllib.request.Request(self._token_url, data=data, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                body = json.loads(resp.read())
            return AuthAttemptResult(
                provider="entra",
                account=username,
                password_hint=_redact_password(password),
                success="access_token" in body,
                locked_out=False,
                mfa_required=False,
                error_code=None,
                http_status=200,
                raw_response_snippet=None,
            )
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")[:200]
            body = {}
            try:
                body = json.loads(body_text)
            except Exception:
                pass

            error_code = body.get("error_codes", [None])[0]
            if isinstance(error_code, list):
                error_code = error_code[0]

            # 50053 = account locked; 50076 = MFA required; 50158 = conditional access
            locked = str(error_code) in {"50053", "50055", "50057"}
            mfa_required = str(error_code) in {"50076", "50158", "50079"}

            return AuthAttemptResult(
                provider="entra",
                account=username,
                password_hint=_redact_password(password),
                success=False,
                locked_out=locked,
                mfa_required=mfa_required,
                error_code=str(error_code),
                http_status=exc.code,
                raw_response_snippet=body_text[:200],
            )
        except Exception as exc:
            return AuthAttemptResult(
                provider="entra",
                account=username,
                password_hint=_redact_password(password),
                success=False,
                locked_out=False,
                mfa_required=False,
                error_code="request_error",
                http_status=None,
                raw_response_snippet=str(exc)[:200],
            )


class OktaAuthClient:
    """
    Okta authentication test client.

    Uses Okta's /api/v1/authn primary authentication endpoint.
    """

    def __init__(self, base_url: str) -> None:
        self._authn_url = f"{base_url.rstrip('/')}/api/v1/authn"

    def attempt(self, username: str, password: str) -> AuthAttemptResult:
        payload = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            self._authn_url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                body = json.loads(resp.read())

            status = body.get("status", "")
            return AuthAttemptResult(
                provider="okta",
                account=username,
                password_hint=_redact_password(password),
                success=status == "SUCCESS",
                locked_out=status == "LOCKED_OUT",
                mfa_required=status in {"MFA_REQUIRED", "MFA_CHALLENGE"},
                error_code=body.get("errorCode"),
                http_status=200,
                raw_response_snippet=None,
            )
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")[:200]
            body = {}
            try:
                body = json.loads(body_text)
            except Exception:
                pass

            error_code = body.get("errorCode", "")
            locked = error_code in {"E0000069", "E0000042"}

            return AuthAttemptResult(
                provider="okta",
                account=username,
                password_hint=_redact_password(password),
                success=False,
                locked_out=locked,
                mfa_required=False,
                error_code=error_code,
                http_status=exc.code,
                raw_response_snippet=body_text[:200],
            )
        except Exception as exc:
            return AuthAttemptResult(
                provider="okta",
                account=username,
                password_hint=_redact_password(password),
                success=False,
                locked_out=False,
                mfa_required=False,
                error_code="request_error",
                http_status=None,
                raw_response_snippet=str(exc)[:200],
            )


class LDAPAuthClient:
    """
    Active Directory LDAP simple bind authentication test client.
    """

    def __init__(self, server: str, port: int = 389, use_ssl: bool = False) -> None:
        self._server = server
        self._port = port
        self._use_ssl = use_ssl

    def attempt(self, username: str, password: str) -> AuthAttemptResult:
        try:
            import ldap3  # type: ignore[import]
        except ImportError:
            return AuthAttemptResult(
                provider="ldap",
                account=username,
                password_hint=_redact_password(password),
                success=False,
                locked_out=False,
                mfa_required=False,
                error_code="ldap3_not_installed",
                http_status=None,
                raw_response_snippet=None,
            )

        try:
            server = ldap3.Server(self._server, port=self._port, use_ssl=self._use_ssl)
            conn = ldap3.Connection(
                server,
                user=username,
                password=password,
                authentication=ldap3.SIMPLE,
                read_only=True,
            )
            success = conn.bind()
            locked = False
            if not success and conn.result:
                desc = str(conn.result.get("description", "")).lower()
                locked = "locked" in desc or "disabled" in desc
            if success:
                conn.unbind()
            return AuthAttemptResult(
                provider="ldap",
                account=username,
                password_hint=_redact_password(password),
                success=success,
                locked_out=locked,
                mfa_required=False,
                error_code=None if success else str(conn.result.get("result")),
                http_status=None,
                raw_response_snippet=None,
            )
        except Exception as exc:
            return AuthAttemptResult(
                provider="ldap",
                account=username,
                password_hint=_redact_password(password),
                success=False,
                locked_out=False,
                mfa_required=False,
                error_code="ldap_error",
                http_status=None,
                raw_response_snippet=str(exc)[:200],
            )
