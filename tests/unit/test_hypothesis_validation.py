# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests — Phase 1.2: Hypothesis validation against GNAT's API."""
from __future__ import annotations

import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from redgnat.feedback.investigation_context import validate_hypothesis

GNAT_URL = "http://gnat.test:8000"
API_KEY = "test-key"
INV_ID = "IC-2026-0001"
HYP_ID = "HYP-2026-0001-01"

_HYPOTHESES_PAYLOAD = json.dumps(
    [{"id": HYP_ID, "title": "Spray goes undetected"}]
).encode()


def _mock_urlopen(payload: bytes, status: int = 200):
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = payload
    resp.status = status
    return resp


class TestValidateHypothesis:
    @patch("urllib.request.urlopen")
    def test_hypothesis_found_returns_true(self, mock_open):
        mock_open.return_value = _mock_urlopen(_HYPOTHESES_PAYLOAD)
        valid, msg = validate_hypothesis(GNAT_URL, API_KEY, INV_ID, HYP_ID)
        assert valid is True
        assert msg is None

    @patch("urllib.request.urlopen")
    def test_hypothesis_not_in_list_returns_false(self, mock_open):
        mock_open.return_value = _mock_urlopen(
            json.dumps([{"id": "HYP-OTHER"}]).encode()
        )
        valid, msg = validate_hypothesis(GNAT_URL, API_KEY, INV_ID, HYP_ID)
        assert valid is False
        assert HYP_ID in msg

    @patch("urllib.request.urlopen")
    def test_investigation_not_found_404_returns_false(self, mock_open):
        mock_open.side_effect = urllib.error.HTTPError(
            url=None, code=404, msg="Not Found", hdrs=None, fp=None
        )
        valid, msg = validate_hypothesis(GNAT_URL, API_KEY, INV_ID, HYP_ID)
        assert valid is False
        assert "404" in msg

    @patch("urllib.request.urlopen")
    def test_gnat_500_returns_none_pending(self, mock_open):
        mock_open.side_effect = urllib.error.HTTPError(
            url=None, code=500, msg="Server Error", hdrs=None, fp=None
        )
        valid, msg = validate_hypothesis(GNAT_URL, API_KEY, INV_ID, HYP_ID)
        assert valid is None
        assert msg is not None

    @patch("urllib.request.urlopen")
    def test_network_error_returns_none_pending(self, mock_open):
        mock_open.side_effect = OSError("connection refused")
        valid, msg = validate_hypothesis(GNAT_URL, API_KEY, INV_ID, HYP_ID)
        assert valid is None
        assert "pending" in msg.lower()

    @patch("urllib.request.urlopen")
    def test_hypothesis_id_in_dict_field(self, mock_open):
        """Handles both 'id' and 'hypothesis_id' key variants."""
        payload = json.dumps([{"hypothesis_id": HYP_ID}]).encode()
        mock_open.return_value = _mock_urlopen(payload)
        valid, msg = validate_hypothesis(GNAT_URL, API_KEY, INV_ID, HYP_ID)
        assert valid is True
