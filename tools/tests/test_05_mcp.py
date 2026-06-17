"""Unit tests for the MCP exploit mapper.

Tool name: 05_mcp_exploit_mapper tests
OWASP coverage: LLM01, LLM06
MITRE mapping: mocked AML.T0017 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from tests.support import load_tool_module

mcp = load_tool_module("05_mcp_exploit_mapper.py", "tool_05_mcp")


class McpTests(unittest.TestCase):
    def test_tool_named_bash_execute_is_critical(self) -> None:
        severity, _class_name = mcp.classify_tool_name("bash_execute")
        self.assertEqual(severity, "critical")

    @patch.object(mcp, "_rpc")
    def test_path_traversal_tool_name_accepted_is_critical(self, mock_rpc: unittest.mock.Mock) -> None:
        mock_rpc.side_effect = [
            {"status": 200, "result": {"tools": []}},
            {"status": 200, "result": {"ok": True}},
        ]
        findings = mcp.scan_target("https://mcp.example.com")
        self.assertTrue(any(f.severity == "critical" for f in findings))

    @patch.object(mcp, "_rpc")
    def test_unauthenticated_tool_list_is_high(self, mock_rpc: unittest.mock.Mock) -> None:
        mock_rpc.return_value = {
            "status": 200,
            "result": {"tools": [{"name": "read_file"}]},
        }
        findings = mcp.scan_target("https://mcp.example.com")
        self.assertTrue(any(f.severity == "high" for f in findings))


if __name__ == "__main__":
    unittest.main()

