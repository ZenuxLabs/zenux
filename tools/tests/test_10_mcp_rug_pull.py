"""Unit tests for the MCP rug-pull detector.

Tool name: 10_mcp_rug_pull_detector tests
OWASP coverage: LLM07
MITRE mapping: mocked AML.T0051 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from tests.support import load_tool_module

mcp_rug_pull = load_tool_module("10_mcp_rug_pull_detector.py", "tool_10_mcp_rug_pull")


class McpRugPullTests(unittest.TestCase):
    @patch.object(mcp_rug_pull.time, "sleep")
    @patch.object(mcp_rug_pull, "probe_tool_shadowing")
    @patch.object(mcp_rug_pull, "fetch_tool_manifest")
    def test_added_tool_creates_added_finding(
        self,
        mock_manifest: MagicMock,
        mock_shadowing: MagicMock,
        _mock_sleep: MagicMock,
    ) -> None:
        mock_manifest.side_effect = [
            {"read_file": {"name": "read_file", "tool_version": "v1"}},
            {
                "read_file": {"name": "read_file", "tool_version": "v1"},
                "bash_execute": {"name": "bash_execute", "tool_version": "v1"},
            },
        ]
        mock_shadowing.return_value = None

        findings = mcp_rug_pull.run_scan("mcp.example.com:8080")

        added = [finding for finding in findings if finding.mutation_type == "added"]
        self.assertEqual(len(added), 1)
        self.assertIn("bash_execute", added[0].title)
        self.assertEqual(added[0].severity, "critical")

    @patch.object(mcp_rug_pull.time, "sleep")
    @patch.object(mcp_rug_pull, "probe_tool_shadowing")
    @patch.object(mcp_rug_pull, "fetch_tool_manifest")
    def test_modified_tool_creates_modified_finding(
        self,
        mock_manifest: MagicMock,
        mock_shadowing: MagicMock,
        _mock_sleep: MagicMock,
    ) -> None:
        mock_manifest.side_effect = [
            {"read_file": {"name": "read_file", "description": "safe", "tool_version": "v1"}},
            {"read_file": {"name": "read_file", "description": "mutated", "tool_version": "v1"}},
        ]
        mock_shadowing.return_value = None

        findings = mcp_rug_pull.run_scan("mcp.example.com:8080")

        modified = [finding for finding in findings if finding.mutation_type == "modified"]
        self.assertEqual(len(modified), 1)
        self.assertEqual(modified[0].severity, "critical")
        self.assertTrue(modified[0].etdi_signed)

    @patch.object(mcp_rug_pull.time, "sleep")
    @patch.object(mcp_rug_pull, "probe_tool_shadowing")
    @patch.object(mcp_rug_pull, "fetch_tool_manifest")
    def test_shadowed_tool_creates_shadowed_finding(
        self,
        mock_manifest: MagicMock,
        mock_shadowing: MagicMock,
        _mock_sleep: MagicMock,
    ) -> None:
        manifest = {
            "read_file": {"name": "read_file", "tool_version": "v1"},
            "search": {"name": "search", "tool_version": "v1"},
        }
        mock_manifest.side_effect = [manifest, manifest]
        mock_shadowing.return_value = "search"

        findings = mcp_rug_pull.run_scan("mcp.example.com:8080")

        shadowed = [finding for finding in findings if finding.mutation_type == "shadowed"]
        self.assertEqual(len(shadowed), 1)
        self.assertIn("CVE-2025-6514", shadowed[0].title)
        self.assertEqual(shadowed[0].severity, "critical")

    @patch.object(mcp_rug_pull.time, "sleep")
    @patch.object(mcp_rug_pull, "probe_tool_shadowing")
    @patch.object(mcp_rug_pull, "fetch_tool_manifest")
    def test_unsigned_tool_creates_medium_finding(
        self,
        mock_manifest: MagicMock,
        mock_shadowing: MagicMock,
        _mock_sleep: MagicMock,
    ) -> None:
        manifest = {"read_file": {"name": "read_file", "description": "no signature"}}
        mock_manifest.side_effect = [manifest, manifest]
        mock_shadowing.return_value = None

        findings = mcp_rug_pull.run_scan("mcp.example.com:8080")

        unsigned = [finding for finding in findings if finding.mutation_type == "unsigned"]
        self.assertEqual(len(unsigned), 1)
        self.assertEqual(unsigned[0].severity, "medium")
        self.assertFalse(unsigned[0].etdi_signed)


if __name__ == "__main__":
    unittest.main()
