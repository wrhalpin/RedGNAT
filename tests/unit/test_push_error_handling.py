# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests — Phase 3.2: Error handling on the investigation evidence push path."""
from __future__ import annotations

import urllib.error
from unittest.mock import patch

import pytest

from redgnat.feedback.investigation_context import push_investigation_bundle

GNAT_URL = "http://gnat.test:8000"
API_KEY = "test-key"
INV_ID = "IC-2026-0001"
BUNDLE = {"type": "bundle", "spec_version": "2.1", "id": "bundle--abc", "objects": []}


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url=None, code=code, msg="error", hdrs=None, fp=None)


class TestPushInvestigationBundle:
    @patch("urllib.request.urlopen")
    def test_success_returns_true(self, mock_open):
        resp = mock_open.return_value.__enter__.return_value
        resp.read.return_value = b"{}"
        ok, err = push_investigation_bundle(GNAT_URL, API_KEY, INV_ID, BUNDLE)
        assert ok is True
        assert err is None

    @patch("urllib.request.urlopen")
    def test_409_conflict_returns_conflict(self, mock_open):
        mock_open.side_effect = _http_error(409)
        ok, err = push_investigation_bundle(GNAT_URL, API_KEY, INV_ID, BUNDLE)
        assert ok is False
        assert err == "conflict"

    @patch("urllib.request.urlopen")
    def test_404_not_found_returns_not_found(self, mock_open):
        mock_open.side_effect = _http_error(404)
        ok, err = push_investigation_bundle(GNAT_URL, API_KEY, INV_ID, BUNDLE)
        assert ok is False
        assert err == "not_found"

    @patch("urllib.request.urlopen")
    def test_403_forbidden_returns_forbidden(self, mock_open):
        mock_open.side_effect = _http_error(403)
        ok, err = push_investigation_bundle(GNAT_URL, API_KEY, INV_ID, BUNDLE)
        assert ok is False
        assert err == "forbidden"

    @patch("urllib.request.urlopen")
    def test_network_error_returns_network_error(self, mock_open):
        mock_open.side_effect = OSError("connection refused")
        ok, err = push_investigation_bundle(GNAT_URL, API_KEY, INV_ID, BUNDLE)
        assert ok is False
        assert err == "network_error"

    @patch("urllib.request.urlopen")
    def test_reopen_header_sent(self, mock_open):
        resp = mock_open.return_value.__enter__.return_value
        resp.read.return_value = b"{}"
        push_investigation_bundle(GNAT_URL, API_KEY, INV_ID, BUNDLE, reopen=True)
        call_args = mock_open.call_args
        req = call_args[0][0]
        assert req.get_header("X-reopen-investigation") == "true"
