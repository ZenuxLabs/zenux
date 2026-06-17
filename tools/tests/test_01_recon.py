"""Unit tests for AI infrastructure recon.

Tool name: 01_ai_infrastructure_recon tests
OWASP coverage: LLM03, LLM07
MITRE mapping: mocked AML.T0007 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests

from tests.support import load_tool_module

recon = load_tool_module("01_ai_infrastructure_recon.py", "tool_01_recon")


class ReconTests(unittest.TestCase):
    def test_detects_ollama_from_response_body(self) -> None:
        stack = recon.classify_stack({"headers": {}, "body_snippet": '{"models":[{"name":"llama3"}]}'})
        self.assertEqual(stack, "Ollama")

    def test_detects_openai_compatible_from_object_list(self) -> None:
        stack = recon.classify_stack({"headers": {}, "body_snippet": '{"object":"list","data":[{"id":"gpt-4"}]}'})
        self.assertEqual(stack, "OpenAI-compatible")

    def test_unauthenticated_api_show_creates_high_finding(self) -> None:
        findings = recon.analyze_discovery_response(
            "http://api.example.com:11434/api/show",
            {"status": 200, "headers": {}, "body_snippet": '{"modelfile":"FROM llama3"}'},
            unauthenticated=False,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].className, "data_exfiltration")

    @patch.object(requests.Session, "get")
    def test_chroma_unauthenticated_is_critical(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = [
            SimpleNamespace(status_code=200),
            RuntimeError("closed"),
            RuntimeError("closed"),
            RuntimeError("closed"),
        ]

        findings = recon.check_vector_db_auth("api.example.com", requests.Session())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Chroma Vector DB Unauthenticated")
        self.assertEqual(findings[0].severity, "critical")

    @patch.object(requests.Session, "get")
    def test_weaviate_anonymous_mode_is_critical(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = [
            RuntimeError("closed"),
            SimpleNamespace(status_code=404),
            SimpleNamespace(status_code=200),
            RuntimeError("closed"),
        ]

        findings = recon.check_vector_db_auth("api.example.com", requests.Session())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Weaviate Vector DB Anonymous Access Enabled")
        self.assertEqual(findings[0].severity, "critical")

    @patch.object(requests.Session, "get")
    def test_qdrant_unauthenticated_is_critical(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = [
            RuntimeError("closed"),
            RuntimeError("closed"),
            SimpleNamespace(status_code=200),
            RuntimeError("closed"),
        ]

        findings = recon.check_vector_db_auth("api.example.com", requests.Session())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Qdrant Vector DB Unauthenticated")
        self.assertEqual(findings[0].severity, "critical")

    @patch.object(requests.Session, "get")
    @patch.object(socket, "create_connection")
    def test_milvus_unencrypted_is_high(
        self,
        mock_connect: MagicMock,
        mock_get: MagicMock,
    ) -> None:
        mock_connect.return_value = SimpleNamespace(close=lambda: None)
        mock_get.side_effect = [
            RuntimeError("closed"),
            RuntimeError("closed"),
            RuntimeError("closed"),
            SimpleNamespace(status_code=200),
        ]

        findings = recon.check_vector_db_auth("api.example.com", requests.Session())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Milvus Vector DB Unencrypted")
        self.assertEqual(findings[0].severity, "high")


if __name__ == "__main__":
    unittest.main()
