"""Unit tests for the unbounded consumption prober.

Tool name: 08_unbounded_consumption_prober tests
OWASP coverage: LLM10
MITRE mapping: mocked AML.T0029 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from tests.support import load_tool_module

consumption = load_tool_module("08_unbounded_consumption_prober.py", "tool_08_consumption")


class ConsumptionTests(unittest.TestCase):
    @patch.object(consumption, "run_concurrent_probe")
    @patch.object(consumption, "_post_probe")
    def test_response_time_over_8_seconds_creates_finding(self, mock_post: unittest.mock.Mock, mock_concurrent: unittest.mock.Mock) -> None:
        mock_post.side_effect = [
            {"status": 200, "text": "ok", "elapsed": 8.5},
            {"status": 400, "text": "recursion blocked", "elapsed": 1.0},
            {"status": 400, "text": "blocked", "elapsed": 1.0},
            {"status": 429, "text": "rate limit", "elapsed": 1.0},
            {"status": 400, "text": "cutoff", "elapsed": 1.0},
            {"status": 413, "text": "too large", "elapsed": 1.0},
        ]
        mock_concurrent.return_value = [{"status": 429}] * 5
        findings = consumption.scan_endpoint("https://api.example.com/v1/chat/completions")
        self.assertTrue(any("max_tokens" in f.title for f in findings))

    @patch.object(consumption, "run_concurrent_probe")
    @patch.object(consumption, "_post_probe")
    def test_concurrent_200s_with_no_rate_limit_is_medium(self, mock_post: unittest.mock.Mock, mock_concurrent: unittest.mock.Mock) -> None:
        mock_post.side_effect = [{"status": 400, "text": "blocked", "elapsed": 1.0}] * 6
        mock_concurrent.return_value = [{"status": 200, "text": "ok"}] * 5
        findings = consumption.scan_endpoint("https://api.example.com/v1/chat/completions")
        self.assertTrue(any(f.severity == "medium" and "rate limit" in f.title.lower() for f in findings))

    @patch.object(consumption, "run_concurrent_probe")
    @patch.object(consumption, "_post_probe")
    def test_fifty_k_context_accepted_is_high(self, mock_post: unittest.mock.Mock, mock_concurrent: unittest.mock.Mock) -> None:
        mock_post.side_effect = [
            {"status": 400, "text": "blocked", "elapsed": 1.0},
            {"status": 400, "text": "blocked", "elapsed": 1.0},
            {"status": 400, "text": "blocked", "elapsed": 1.0},
            {"status": 400, "text": "blocked", "elapsed": 1.0},
            {"status": 400, "text": "blocked", "elapsed": 1.0},
            {"status": 200, "text": "accepted", "elapsed": 1.0},
        ]
        mock_concurrent.return_value = [{"status": 429, "text": "rate limited"}] * 5
        findings = consumption.scan_endpoint("https://api.example.com/v1/chat/completions")
        self.assertTrue(any(f.severity == "high" and "oversized context" in f.title.lower() for f in findings))


if __name__ == "__main__":
    unittest.main()
