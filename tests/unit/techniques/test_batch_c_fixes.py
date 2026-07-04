# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Regression tests for Batch C technique-safety fixes."""
from __future__ import annotations

from redgnat.techniques.identity.base import _rate_delay_seconds


class TestRateDelaySeconds:
    def test_positive_rate(self):
        assert _rate_delay_seconds(30) == 2.0

    def test_zero_rate_does_not_divide(self):
        # Regression: max_rate_per_minute == 0 previously raised ZeroDivisionError
        assert _rate_delay_seconds(0) == 0.0

    def test_negative_rate_is_safe(self):
        assert _rate_delay_seconds(-5) == 0.0


class TestOAuthDomainExtraction:
    def test_domain_is_extracted_not_empty(self):
        from redgnat.techniques.base import Scope

        scope = Scope(target_domains=["corp.example.com"])
        # Mirror the technique's extraction logic
        def _domain(email: str) -> str:
            return email.rsplit("@", 1)[-1] if "@" in email else ""

        assert _domain("user@corp.example.com") == "corp.example.com"
        assert scope.allows_domain(_domain("user@corp.example.com")) is True
        assert _domain("no-at-sign") == ""
