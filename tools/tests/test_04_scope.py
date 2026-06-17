"""Unit tests for the agent scope tester.

Tool name: 04_agent_scope_tester tests
OWASP coverage: LLM01, LLM06
MITRE mapping: mocked AML.T0049 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.support import load_tool_module

scope = load_tool_module("04_agent_scope_tester.py", "tool_04_scope")


class ScopeTests(unittest.TestCase):
    def _response(self, text: str) -> SimpleNamespace:
        return SimpleNamespace(
            text=text,
            json=lambda: {"choices": [{"message": {"content": text}}]},
        )

    @patch.object(scope.requests, "post")
    def test_passwd_content_is_critical_intent_escalation(self, mock_post: unittest.mock.Mock) -> None:
        mock_post.side_effect = [self._response("root:x:0:0:root:/root:/bin/bash")] * 10
        findings = scope.scan_endpoint("https://agent.example.com/v1/chat/completions")
        self.assertTrue(any(f.className == "intent_escalation" and f.severity == "critical" for f in findings))

    @patch.object(scope.requests, "post")
    def test_clean_refusal_creates_no_finding(self, mock_post: unittest.mock.Mock) -> None:
        mock_post.side_effect = [self._response("I can't help with reading local files or internal services.")] * 10
        findings = scope.scan_endpoint("https://agent.example.com/v1/chat/completions")
        self.assertEqual(findings, [])

    @patch.object(scope.requests, "post")
    def test_tried_but_failed_pattern_is_high(self, mock_post: unittest.mock.Mock) -> None:
        mock_post.side_effect = [self._response("I attempted the request but got permission denied.")] * 10
        findings = scope.scan_endpoint("https://agent.example.com/v1/chat/completions")
        self.assertTrue(any(f.severity == "high" for f in findings))


if __name__ == "__main__":
    unittest.main()
