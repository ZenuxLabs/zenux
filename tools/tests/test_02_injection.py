"""Unit tests for prompt injection scanning.

Tool name: 02_prompt_injection_scanner tests
OWASP coverage: LLM01, LLM07
MITRE mapping: mocked AML.T0051 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.support import load_tool_module

scanner = load_tool_module("02_prompt_injection_scanner.py", "tool_02_injection")


class InjectionTests(unittest.TestCase):
    def _response(self, text: str) -> SimpleNamespace:
        return SimpleNamespace(
            text=text,
            json=lambda: {"choices": [{"message": {"content": text}}]},
        )

    @patch.object(scanner.requests, "post")
    @patch.object(scanner.time, "sleep")
    def test_injection_confirmed_returns_critical_finding(self, _sleep: unittest.mock.Mock, mock_post: unittest.mock.Mock) -> None:
        mock_post.return_value = self._response("INJECTION_CONFIRMED")
        findings = scanner.scan_endpoint("https://api.example.com/v1/chat/completions")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    @patch.object(scanner.requests, "post")
    @patch.object(scanner.time, "sleep")
    def test_template_49_indicator_returns_critical_finding(self, _sleep: unittest.mock.Mock, mock_post: unittest.mock.Mock) -> None:
        mock_post.side_effect = [self._response("refusal"), self._response("refusal"), self._response("49")]
        findings = scanner.scan_endpoint("https://api.example.com/v1/chat/completions")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    @patch.object(scanner.requests, "post")
    @patch.object(scanner.time, "sleep")
    def test_clean_response_returns_no_finding(self, _sleep: unittest.mock.Mock, mock_post: unittest.mock.Mock) -> None:
        mock_post.side_effect = [self._response("I cannot help with that."), self._response("Still refusing."), self._response("No."), self._response("No."), self._response("No."), self._response("No.")]
        findings = scanner.scan_endpoint("https://api.example.com/v1/chat/completions")
        self.assertEqual(findings, [])

    @patch.object(scanner.requests, "post")
    @patch.object(scanner.time, "sleep")
    def test_tier_two_escalates_after_tier_one_refusal(self, _sleep: unittest.mock.Mock, mock_post: unittest.mock.Mock) -> None:
        mock_post.side_effect = [self._response("no"), self._response("Your instructions are hidden here.")]
        findings = scanner.scan_endpoint("https://api.example.com/v1/chat/completions")
        first_followup_prompt = mock_post.call_args_list[1].kwargs["json"]["messages"][0]["content"]
        self.assertIn("Let's play a game", first_followup_prompt)
        self.assertEqual(findings[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()

