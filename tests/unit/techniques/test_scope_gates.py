# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Scope-gate tests for discovery/identity techniques (Batch C safety fixes)."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Scope, TechniqueContext
from redgnat.techniques.discovery.ad_enum import ADEnumTechnique
from redgnat.techniques.discovery.cloud_enum import CloudEnumTechnique
from redgnat.techniques.identity.token_theft import TokenTheftTechnique


def _ctx(params=None, domains=("corp.example.com",)):
    scope = Scope(target_domains=list(domains), max_rate_per_minute=60)
    return TechniqueContext(
        run_id="r", scenario_id="s", feed_id="f", scope=scope, params=params or {}
    )


class TestADEnumScope:
    @pytest.fixture(autouse=True)
    def _fake_ldap3(self):
        # ad_enum imports ldap3 before the scope check; inject a stub so the
        # scope gate is reachable without the real dependency installed.
        with patch.dict(sys.modules, {"ldap3": MagicMock()}):
            yield

    def _cfg(self, server):
        cfg = MagicMock()
        cfg.ldap_server = server
        cfg.ldap_base_dn = "DC=corp,DC=example,DC=com"
        cfg.ldap_bind_dn = "CN=svc"
        cfg.ldap_bind_password = "pw"
        cfg.ldap_port = 389
        cfg.ldap_use_ssl = False
        return cfg

    def test_out_of_scope_host_blocked(self):
        cfg = self._cfg("ldap://evil.attacker.com")
        with patch("redgnat.config.RedGNATConfig", return_value=cfg):
            result = ADEnumTechnique().execute(_ctx())
        assert result.status == ResultStatus.BLOCKED
        assert "not in scope" in result.findings[0]["reason"]

    def test_params_cannot_override_server(self):
        # cfg host is out of scope; an in-scope host supplied via params must be
        # ignored (server comes from trusted config only) -> still BLOCKED.
        cfg = self._cfg("ldap://evil.attacker.com")
        with patch("redgnat.config.RedGNATConfig", return_value=cfg):
            result = ADEnumTechnique().execute(
                _ctx(params={"ldap_server": "ldap://dc.corp.example.com"})
            )
        assert result.status == ResultStatus.BLOCKED

    def test_not_configured_blocked(self):
        cfg = self._cfg("")
        with patch("redgnat.config.RedGNATConfig", return_value=cfg):
            result = ADEnumTechnique().execute(_ctx())
        assert result.status == ResultStatus.BLOCKED


class TestCloudEnumScope:
    def _cfg(self):
        cfg = MagicMock()
        cfg.entra_tenant_id = "tenant.corp.example.com"
        cfg.okta_base_url = "https://login.corp.example.com"
        cfg.aws_access_key_id = ""
        return cfg

    def test_out_of_scope_tenant_not_enumerated(self):
        t = CloudEnumTechnique()
        with (
            patch("redgnat.config.RedGNATConfig", return_value=self._cfg()),
            patch.object(t, "_enum_entra") as entra,
            patch.object(t, "_enum_okta") as okta,
        ):
            result = t.execute(_ctx(domains=["unrelated.com"]))
        entra.assert_not_called()
        okta.assert_not_called()
        assert result.status == ResultStatus.ERROR

    def test_in_scope_tenant_is_enumerated(self):
        t = CloudEnumTechnique()
        with (
            patch("redgnat.config.RedGNATConfig", return_value=self._cfg()),
            patch.object(t, "_enum_entra", return_value=[{"user": "a"}]) as entra,
            patch.object(t, "_enum_okta", return_value=[]),
        ):
            result = t.execute(_ctx(domains=["corp.example.com"]))
        entra.assert_called_once()
        assert result.status == ResultStatus.SUCCESS

    def test_guid_tenant_is_not_domain_gated(self):
        # A GUID tenant_id (the common case, per config.ini.example) cannot be
        # domain-scoped — the gate must be SKIPPED, not force-block Entra.
        cfg = self._cfg()
        cfg.entra_tenant_id = "11111111-2222-3333-4444-555555555555"
        cfg.okta_base_url = ""
        t = CloudEnumTechnique()
        with (
            patch("redgnat.config.RedGNATConfig", return_value=cfg),
            patch.object(t, "_enum_entra", return_value=[{"user": "a"}]) as entra,
        ):
            result = t.execute(_ctx(domains=["corp.example.com"]))
        entra.assert_called_once()
        assert result.status == ResultStatus.SUCCESS


class TestTokenTheftScope:
    def _cfg(self):
        cfg = MagicMock()
        cfg.entra_tenant_id = "tenant.corp.example.com"
        cfg.okta_base_url = "https://login.corp.example.com"
        return cfg

    def test_out_of_scope_provider_not_analyzed(self):
        t = TokenTheftTechnique()
        with (
            patch("redgnat.config.RedGNATConfig", return_value=self._cfg()),
            patch.object(t, "_analyze_entra") as entra,
            patch.object(t, "_analyze_okta") as okta,
        ):
            result = t.execute(_ctx(domains=["unrelated.com"]))
        entra.assert_not_called()
        okta.assert_not_called()
        # both providers gated out -> no findings; scope reasons recorded in error
        assert result.status == ResultStatus.PARTIAL
        assert "not in scope" in (result.error or "")

    def test_in_scope_provider_analyzed(self):
        t = TokenTheftTechnique()
        with (
            patch("redgnat.config.RedGNATConfig", return_value=self._cfg()),
            patch.object(t, "_analyze_entra", return_value=[{"category": "x"}]) as entra,
            patch.object(t, "_analyze_okta", return_value=[]),
        ):
            result = t.execute(_ctx(domains=["corp.example.com"]))
        entra.assert_called_once()
        assert result.status == ResultStatus.SUCCESS

    def test_guid_tenant_is_not_domain_gated(self):
        # GUID tenant_id -> domain gate skipped, Entra still analyzed.
        cfg = self._cfg()
        cfg.entra_tenant_id = "11111111-2222-3333-4444-555555555555"
        cfg.okta_base_url = ""
        t = TokenTheftTechnique()
        with (
            patch("redgnat.config.RedGNATConfig", return_value=cfg),
            patch.object(t, "_analyze_entra", return_value=[{"category": "x"}]) as entra,
        ):
            result = t.execute(_ctx(domains=["corp.example.com"]))
        entra.assert_called_once()
        assert result.status == ResultStatus.SUCCESS
