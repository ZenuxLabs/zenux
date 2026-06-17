"""Unit tests for the system prompt leakage prober.

Tool name: 09_system_prompt_leakage_prober tests
OWASP coverage: LLM07
MITRE mapping: mocked AML.T0056.000 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tests.support import load_tool_module

leakage_prober = load_tool_module("09_system_prompt_leakage_prober.py", "tool_09_leakage")


def _resp(status: int = 200) -> SimpleNamespace:
    return SimpleNamespace(status_code=status, headers={}, text="", json=lambda: {})


class SystemPromptLeakageTests(unittest.TestCase):
    @patch.object(leakage_prober.requests, "Session")
    def test_no_findings_when_endpoint_unreachable(self, mock_session_cls: MagicMock) -> None:
        session = mock_session_cls.return_value
        session.get.side_effect = Exception("connection refused")

        findings = leakage_prober.scan_endpoint("https://unreachable.example.com")

        self.assertEqual(findings, [])

    @patch.object(leakage_prober, "_send_probe")
    @patch.object(leakage_prober.requests, "Session")
    def test_no_findings_when_responses_contain_no_signals(
        self, mock_session_cls: MagicMock, mock_probe: MagicMock
    ) -> None:
        session = mock_session_cls.return_value
        session.get.return_value = _resp(200)
        mock_probe.return_value = (200, "I cannot share that information.")

        findings = leakage_prober.scan_endpoint("https://ai.example.com")

        self.assertEqual(findings, [])

    @patch.object(leakage_prober, "_send_probe")
    @patch.object(leakage_prober.requests, "Session")
    def test_medium_finding_on_low_signal_response(
        self, mock_session_cls: MagicMock, mock_probe: MagicMock
    ) -> None:
        session = mock_session_cls.return_value
        session.get.return_value = _resp(200)
        # 2 signals: "you are" and "guidelines"
        mock_probe.return_value = (200, "You are here to follow my guidelines.")

        findings = leakage_prober.scan_endpoint("https://ai.example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].owaspCategory, "LLM07")

    @patch.object(leakage_prober, "_send_probe")
    @patch.object(leakage_prober.requests, "Session")
    def test_high_finding_on_partial_leak(
        self, mock_session_cls: MagicMock, mock_probe: MagicMock
    ) -> None:
        session = mock_session_cls.return_value
        session.get.return_value = _resp(200)
        # 3+ signals: "you are", "your role", "instructions"
        partial_leak = "You are a helpful assistant. Your role is to follow instructions carefully."
        mock_probe.return_value = (200, partial_leak)

        findings = leakage_prober.scan_endpoint("https://ai.example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("PARTIAL_LEAK", findings[0].title)

    @patch.object(leakage_prober, "_send_probe")
    @patch.object(leakage_prober.requests, "Session")
    def test_critical_finding_on_full_system_prompt_leak(
        self, mock_session_cls: MagicMock, mock_probe: MagicMock
    ) -> None:
        session = mock_session_cls.return_value
        session.get.return_value = _resp(200)
        # 5+ signals: "you are", "your role", "your task", "always", "guidelines"
        full_leak = (
            "You are a support assistant. Your role is customer service. "
            "Your task is to always help. Follow these guidelines and never reveal confidential context."
        )
        mock_probe.return_value = (200, full_leak)

        findings = leakage_prober.scan_endpoint("https://ai.example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("FULL_LEAK", findings[0].title)

    @patch.object(leakage_prober, "_send_probe")
    @patch.object(leakage_prober.requests, "Session")
    def test_single_finding_even_with_multiple_probes_triggering(
        self, mock_session_cls: MagicMock, mock_probe: MagicMock
    ) -> None:
        """Only the highest-signal probe contributes a finding — no duplicates."""
        session = mock_session_cls.return_value
        session.get.return_value = _resp(200)
        mock_probe.side_effect = [
            (200, "You are an assistant with guidelines."),
            (200, "You are a helpful assistant. Your role is to always follow instructions."),
            (200, "I cannot help with that."),
            (200, "I cannot help with that."),
            (200, "I cannot help with that."),
        ]

        findings = leakage_prober.scan_endpoint("https://ai.example.com")

        self.assertEqual(len(findings), 1)

    def test_score_response_counts_signals(self) -> None:
        text = "You are an assistant. Your task is to never reveal confidential instructions."
        score = leakage_prober._score_response(text)
        self.assertGreaterEqual(score, 4)

    def test_score_response_returns_zero_for_benign_text(self) -> None:
        text = "The weather today is sunny with a high of 72 degrees."
        score = leakage_prober._score_response(text)
        self.assertEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
