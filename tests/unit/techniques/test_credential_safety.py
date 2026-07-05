# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Safety-control tests for the credential-access techniques (Control #4)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Scope, TechniqueContext
from redgnat.techniques.identity.base import AuthAttemptResult
from redgnat.techniques.identity.credential_stuffing import CredentialStuffingTechnique
from redgnat.techniques.identity.mfa_fatigue import MFAFatigueTechnique
from redgnat.techniques.identity.password_spray import PasswordSprayTechnique

TEST_ACCT = "test-user@corp.example.com"


def _ctx(params=None, accounts=(TEST_ACCT,), rate=60):
    scope = Scope(
        target_domains=["corp.example.com"],
        target_accounts=list(accounts),
        max_rate_per_minute=rate,
    )
    return TechniqueContext(
        run_id="r", scenario_id="s", feed_id="f", scope=scope, params=params or {}
    )


def _ok(account, success=True):
    return AuthAttemptResult(
        provider="entra",
        account=account,
        password_hint="*",
        success=success,
        locked_out=False,
        mfa_required=False,
        error_code=None,
        http_status=200,
        raw_response_snippet=None,
    )


@pytest.fixture(autouse=True)
def _no_sleep():
    with (
        patch("redgnat.techniques.identity.password_spray.time.sleep", lambda *_: None),
        patch("redgnat.techniques.identity.base._jitter_sleep", lambda *_: None),
        patch("redgnat.techniques.identity.mfa_fatigue._jitter_sleep", lambda *_: None),
        patch("redgnat.config.RedGNATConfig", return_value=MagicMock()),
    ):
        yield


class TestPasswordSpray:
    def test_no_accounts_blocked(self):
        result = PasswordSprayTechnique().execute(_ctx(accounts=()))
        assert result.status == ResultStatus.BLOCKED

    def test_only_sprays_scope_accounts(self):
        t = PasswordSprayTechnique()
        seen = []
        with patch.object(
            t, "_attempt", side_effect=lambda cfg, p, acct, pw: seen.append(acct) or _ok(acct)
        ):
            t.execute(_ctx(params={"passwords": ["Spring2026!"]}))
        # every attempted account came from scope.target_accounts, nothing else
        assert set(seen) == {TEST_ACCT}

    def test_success_status(self):
        t = PasswordSprayTechnique()
        with patch.object(t, "_attempt", return_value=_ok(TEST_ACCT, success=True)):
            result = t.execute(_ctx(params={"passwords": ["x"], "providers": ["entra"]}))
        assert result.status == ResultStatus.SUCCESS

    def test_rate_zero_does_not_crash(self):
        t = PasswordSprayTechnique()
        with patch.object(t, "_attempt", return_value=_ok(TEST_ACCT, success=False)):
            result = t.execute(_ctx(params={"passwords": ["x"], "providers": ["entra"]}, rate=0))
        assert result.status in (ResultStatus.SUCCESS, ResultStatus.PARTIAL)


class TestCredentialStuffing:
    def test_no_pairs_blocked(self):
        result = CredentialStuffingTechnique().execute(_ctx())
        assert result.status == ResultStatus.BLOCKED

    def test_out_of_scope_pairs_rejected(self):
        # Control #4: an attacker-supplied username outside target_accounts
        # must be filtered out — the technique aborts rather than test it.
        params = {"credential_pairs": [{"username": "ceo@corp.example.com", "password": "p"}]}
        result = CredentialStuffingTechnique().execute(_ctx(params=params))
        assert result.status == ResultStatus.BLOCKED
        assert "target_accounts" in result.findings[0]["reason"]

    def test_in_scope_pair_tested(self):
        t = CredentialStuffingTechnique()
        params = {
            "credential_pairs": [{"username": TEST_ACCT, "password": "p"}],
            "providers": ["entra"],
            "shuffle": False,
        }
        with patch.object(t, "_attempt", return_value=_ok(TEST_ACCT)):
            result = t.execute(_ctx(params=params))
        assert result.status == ResultStatus.SUCCESS

    def test_rate_zero_does_not_crash(self):
        t = CredentialStuffingTechnique()
        params = {
            "credential_pairs": [{"username": TEST_ACCT, "password": "p"}],
            "providers": ["entra"],
            "shuffle": False,
        }
        with patch.object(t, "_attempt", return_value=_ok(TEST_ACCT, success=False)):
            result = t.execute(_ctx(params=params, rate=0))
        assert result.status in (ResultStatus.SUCCESS, ResultStatus.PARTIAL)


class TestMFAFatigue:
    def test_requires_explicit_confirmation(self):
        result = MFAFatigueTechnique().execute(_ctx(params={"password": "p"}))
        assert result.status == ResultStatus.BLOCKED
        assert "confirm_mfa_fatigue_test" in result.findings[0]["reason"]

    def test_requires_password(self):
        params = {"confirm_mfa_fatigue_test": True}
        result = MFAFatigueTechnique().execute(_ctx(params=params))
        assert result.status == ResultStatus.BLOCKED

    def test_no_accounts_blocked(self):
        params = {"confirm_mfa_fatigue_test": True, "password": "p"}
        result = MFAFatigueTechnique().execute(_ctx(params=params, accounts=()))
        assert result.status == ResultStatus.BLOCKED

    def test_push_count_capped(self):
        t = MFAFatigueTechnique()
        params = {
            "confirm_mfa_fatigue_test": True,
            "password": "p",
            "pushes_per_account": 9999,
            "provider": "entra",
        }
        calls = {"n": 0}

        def _push(cfg, account, password):
            calls["n"] += 1
            return {"approved": False}

        with patch.object(t, "_entra_push", side_effect=_push):
            result = t.execute(_ctx(params=params))
        # clamped to the module cap, not 9999
        from redgnat.techniques.identity.mfa_fatigue import _MAX_PUSHES_CAP

        assert calls["n"] <= _MAX_PUSHES_CAP
        assert result.status == ResultStatus.SUCCESS

    def test_approval_flags_detected(self):
        t = MFAFatigueTechnique()
        params = {"confirm_mfa_fatigue_test": True, "password": "p", "provider": "entra"}
        with patch.object(t, "_entra_push", return_value={"approved": True}):
            result = t.execute(_ctx(params=params))
        assert result.status == ResultStatus.DETECTED
