"""Unit tests for the Scope safe-harbor implementation."""
from __future__ import annotations

import pytest

from redgnat.techniques.base import OutOfScopeError, Scope, Technique, TechniqueContext
from redgnat.orm.models import ResultStatus


class _TestTechnique(Technique):
    technique_id = "T0000"
    tactic = "test"
    name = "Test Technique"
    emulation_only = True

    def execute(self, ctx: TechniqueContext):
        return self._make_result(ctx, ResultStatus.SUCCESS, [{"test": True}])


def make_scope(**kwargs) -> Scope:
    defaults = {
        "target_ranges": ["192.168.1.0/24"],
        "excluded_ranges": ["192.168.1.1/32"],
        "target_domains": ["example.com"],
        "excluded_domains": ["prod.example.com"],
        "target_accounts": ["test@example.com"],
        "max_rate_per_minute": 30,
        "dry_run": False,
    }
    defaults.update(kwargs)
    return Scope(**defaults)


class TestScopeIP:
    def test_allows_in_range(self):
        scope = make_scope()
        assert scope.allows_ip("192.168.1.100") is True

    def test_blocks_excluded(self):
        scope = make_scope()
        assert scope.allows_ip("192.168.1.1") is False

    def test_blocks_out_of_range(self):
        scope = make_scope()
        assert scope.allows_ip("10.0.0.1") is False

    def test_blocks_invalid_ip(self):
        scope = make_scope()
        assert scope.allows_ip("not-an-ip") is False


class TestScopeDomain:
    def test_allows_in_scope_domain(self):
        scope = make_scope()
        assert scope.allows_domain("example.com") is True

    def test_allows_subdomain(self):
        scope = make_scope()
        assert scope.allows_domain("mail.example.com") is True

    def test_blocks_excluded_subdomain(self):
        scope = make_scope()
        assert scope.allows_domain("prod.example.com") is False

    def test_blocks_out_of_scope(self):
        scope = make_scope()
        assert scope.allows_domain("other.com") is False


class TestScopeAccount:
    def test_allows_exact_match(self):
        scope = make_scope()
        assert scope.allows_account("test@example.com") is True

    def test_allows_case_insensitive(self):
        scope = make_scope()
        assert scope.allows_account("TEST@EXAMPLE.COM") is True

    def test_blocks_unlisted_account(self):
        scope = make_scope()
        assert scope.allows_account("other@example.com") is False


class TestTechniqueScopeGuard:
    def test_check_scope_ip_raises_for_out_of_scope(self):
        t = _TestTechnique()
        scope = make_scope()
        with pytest.raises(OutOfScopeError):
            t._check_scope_ip(scope, "10.0.0.1")

    def test_check_scope_domain_raises_for_out_of_scope(self):
        t = _TestTechnique()
        scope = make_scope()
        with pytest.raises(OutOfScopeError):
            t._check_scope_domain(scope, "other.com")

    def test_check_scope_account_raises_for_unlisted(self):
        t = _TestTechnique()
        scope = make_scope()
        with pytest.raises(OutOfScopeError):
            t._check_scope_account(scope, "attacker@evil.com")

    def test_dry_run_result(self):
        t = _TestTechnique()
        scope = make_scope(dry_run=True)
        ctx = TechniqueContext(
            run_id="r1", scenario_id="s1", feed_id="f1", scope=scope
        )
        result = t._dry_run_result(ctx, "would do something")
        assert result.status == ResultStatus.DRY_RUN
        assert result.findings[0]["dry_run"] is True

    def test_blocked_result(self):
        t = _TestTechnique()
        scope = make_scope()
        ctx = TechniqueContext(
            run_id="r1", scenario_id="s1", feed_id="f1", scope=scope
        )
        result = t._blocked_result(ctx, "no targets")
        assert result.status == ResultStatus.BLOCKED
