"""Unit tests for the LLMjacking & AI credential abuse detector.

Tool name: 13_llmjacking_credential_detector tests
OWASP coverage: LLM10
MITRE mapping: mocked AML.T0040 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

from tests.support import load_tool_module

detector = load_tool_module("13_llmjacking_credential_detector.py", "tool_13_llmjacking")


class UnauthenticatedEndpointTests(unittest.TestCase):
    """Tests for unauthenticated endpoint detection."""

    @patch.object(detector.requests, "post")
    def test_open_endpoint_is_critical(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"choices": [{"message": {"content": "hello"}}]}'
        mock_post.return_value = mock_response

        issues = detector.probe_unauthenticated_endpoint("https://api.example.com")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "unauthenticated_endpoint")
        self.assertEqual(issues[0]["severity"], "critical")

    @patch.object(detector.requests, "post")
    def test_authenticated_endpoint_no_issue(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = '{"error": "unauthorized"}'
        mock_post.return_value = mock_response

        issues = detector.probe_unauthenticated_endpoint("https://api.example.com")
        self.assertEqual(len(issues), 0)

    @patch.object(detector.requests, "post", side_effect=detector.requests.RequestException)
    def test_connection_error_no_issue(self, _mock: MagicMock) -> None:
        issues = detector.probe_unauthenticated_endpoint("https://unreachable.example.com")
        self.assertEqual(len(issues), 0)


class UnboundedMaxTokensTests(unittest.TestCase):
    """Tests for unbounded max_tokens acceptance."""

    @patch.object(detector.requests, "post")
    def test_accepted_max_tokens_is_high(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"choices": [{"message": {"content": "hi"}}]}'
        mock_post.return_value = mock_response

        issues = detector.probe_unbounded_max_tokens("https://api.example.com", {})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "unbounded_max_tokens")
        self.assertEqual(issues[0]["severity"], "high")

    @patch.object(detector.requests, "post")
    def test_rejected_max_tokens_no_issue(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = '{"error": "max_tokens exceeds limit"}'
        mock_post.return_value = mock_response

        issues = detector.probe_unbounded_max_tokens("https://api.example.com", {})
        self.assertEqual(len(issues), 0)


class CredentialEchoTests(unittest.TestCase):
    """Tests for credential echo in error responses."""

    @patch.object(detector.requests, "post")
    def test_openai_key_echo_is_critical(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = 'Error: invalid key sk-abc123def456ghi789jkl012mno345'
        mock_post.return_value = mock_response

        issues = detector.probe_credential_echo("https://api.example.com", {})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "credential_echo")
        self.assertEqual(issues[0]["severity"], "critical")

    @patch.object(detector.requests, "post")
    def test_clean_error_no_issue(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = '{"error": "model not found"}'
        mock_post.return_value = mock_response

        issues = detector.probe_credential_echo("https://api.example.com", {})
        self.assertEqual(len(issues), 0)


class CredentialFileScanTests(unittest.TestCase):
    """Tests for credential file scanning."""

    def test_openai_key_in_env_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text(
                "OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr\nDATABASE_URL=postgres://...",
                encoding="utf-8",
            )

            issues = detector.scan_credential_files(tmpdir)
            self.assertTrue(len(issues) >= 1)
            openai_issues = [i for i in issues if i["detail"] and "OpenAI" in i["detail"]]
            self.assertTrue(len(openai_issues) >= 1)

    def test_anthropic_key_in_docker_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            compose_path = Path(tmpdir) / "docker-compose.yml"
            compose_path.write_text(
                "services:\n  api:\n    environment:\n"
                "      - ANTHROPIC_KEY=sk-ant-abc123def456ghi789jkl012mno345pqr\n",
                encoding="utf-8",
            )

            issues = detector.scan_credential_files(tmpdir)
            self.assertTrue(len(issues) >= 1)
            anthro = [i for i in issues if "Anthropic" in i.get("detail", "")]
            self.assertTrue(len(anthro) >= 1)

    def test_aws_key_in_env_local(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env.local"
            env_path.write_text(
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET=something",
                encoding="utf-8",
            )

            issues = detector.scan_credential_files(tmpdir)
            aws_issues = [i for i in issues if "AWS" in i.get("detail", "")]
            self.assertTrue(len(aws_issues) >= 1)

    def test_google_ai_key_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text(
                "GOOGLE_API_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuvwx\n",
                encoding="utf-8",
            )

            issues = detector.scan_credential_files(tmpdir)
            google_issues = [i for i in issues if "Google" in i.get("detail", "")]
            self.assertTrue(len(google_issues) >= 1)

    def test_clean_env_no_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text(
                "DATABASE_URL=postgres://localhost:5432/mydb\nPORT=3000\n",
                encoding="utf-8",
            )

            issues = detector.scan_credential_files(tmpdir)
            self.assertEqual(len(issues), 0)

    def test_nonexistent_directory(self) -> None:
        issues = detector.scan_credential_files("/nonexistent/path/xyz")
        self.assertEqual(len(issues), 0)


class ScanFilesIntegrationTests(unittest.TestCase):
    """Tests for the scan_files entry point."""

    def test_scan_files_returns_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text(
                "OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr\n",
                encoding="utf-8",
            )

            findings = detector.scan_files(tmpdir)
            self.assertTrue(len(findings) >= 1)
            self.assertEqual(findings[0].owaspCategory, "LLM10")
            self.assertEqual(findings[0].className, "credential_theft")


class ScanTargetRoutingTests(unittest.TestCase):
    """Tests for scan_target dispatch logic."""

    @patch.object(detector, "scan_files")
    def test_directory_target_routes_to_scan_files(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = []
        with tempfile.TemporaryDirectory() as tmpdir:
            detector.scan_target(tmpdir)
            mock_scan.assert_called_once_with(tmpdir)

    @patch.object(detector, "scan_endpoint")
    def test_url_target_routes_to_scan_endpoint(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = []
        detector.scan_target("https://api.example.com")
        mock_scan.assert_called_once_with("https://api.example.com", None)


if __name__ == "__main__":
    unittest.main()
