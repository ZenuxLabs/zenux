"""Unit tests for the LiteLLM policy probe.

Tool name: 11_litellm_policy_probe tests
OWASP coverage: LLM01, LLM05
MITRE mapping: mocked gateway policy validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tests.support import load_tool_module

litellm_probe = load_tool_module("11_litellm_policy_probe.py", "tool_11_litellm")


class LiteLLMProbeTests(unittest.TestCase):
    def _response(
        self,
        *,
        status_code: int = 200,
        payload: object | None = None,
        text: str = "",
        headers: dict[str, str] | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            status_code=status_code,
            headers=headers or {},
            text=text,
            json=lambda: payload,
        )

    @patch.object(litellm_probe.requests, "Session")
    def test_missing_guardrails_creates_critical_finding(self, mock_session_cls: MagicMock) -> None:
        session = mock_session_cls.return_value
        session.get.side_effect = [
            self._response(status_code=200, payload={"status": "ok"}),
            self._response(status_code=404, payload=None, text="not found"),
        ]
        session.post.side_effect = [
            self._response(status_code=400, text="blocked by policy"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
        ]

        findings = litellm_probe.scan_target("https://litellm.example.com", auth_header="Authorization: Bearer token")

        self.assertTrue(any("LITELLM_NO_GUARDRAILS" in finding.title and finding.severity == "critical" for finding in findings))

    @patch.object(litellm_probe.requests, "Session")
    def test_injection_bypass_creates_critical_finding(self, mock_session_cls: MagicMock) -> None:
        session = mock_session_cls.return_value
        session.get.side_effect = [
            self._response(status_code=200, payload={"status": "ok"}),
            self._response(status_code=200, payload={"guardrails": [{"name": "prompt-injection-check"}]}),
        ]
        session.post.side_effect = [
            self._response(status_code=200, text="PWNED", headers={"x-hiddenlayer-policy": "enforced"}),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
        ]

        findings = litellm_probe.scan_target("https://litellm.example.com", auth_header="Authorization: Bearer token")

        self.assertTrue(any("LITELLM_INJECTION_BYPASS" in finding.title and finding.severity == "critical" for finding in findings))

    @patch.object(litellm_probe.requests, "Session")
    def test_missing_rate_limit_creates_medium_finding(self, mock_session_cls: MagicMock) -> None:
        session = mock_session_cls.return_value
        session.get.side_effect = [
            self._response(status_code=200, payload={"status": "ok"}),
            self._response(status_code=200, payload={"guardrails": [{"name": "prompt-injection-check"}]}),
        ]
        session.post.side_effect = [
            self._response(status_code=400, text="blocked by policy"),
            self._response(status_code=200, text="ok"),
            self._response(status_code=200, text="ok"),
            self._response(status_code=200, text="ok"),
            self._response(status_code=200, text="ok"),
            self._response(status_code=200, text="ok"),
        ]

        findings = litellm_probe.scan_target("https://litellm.example.com", auth_header="Authorization: Bearer token")

        self.assertTrue(any("LITELLM_NO_RATE_LIMIT" in finding.title and finding.severity == "medium" for finding in findings))

    @patch.object(litellm_probe.requests, "Session")
    def test_unauthenticated_proxy_creates_high_finding(self, mock_session_cls: MagicMock) -> None:
        session = mock_session_cls.return_value
        session.get.side_effect = [
            self._response(status_code=200, payload={"status": "ok"}),
            self._response(status_code=200, payload={"guardrails": [{"name": "prompt-injection-check"}]}),
        ]
        session.post.side_effect = [
            self._response(status_code=200, text="request accepted"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
            self._response(status_code=429, text="rate limited"),
        ]

        findings = litellm_probe.scan_target("https://litellm.example.com")

        self.assertTrue(any("LITELLM_UNAUTHENTICATED" in finding.title and finding.severity == "high" for finding in findings))


if __name__ == "__main__":
    unittest.main()
