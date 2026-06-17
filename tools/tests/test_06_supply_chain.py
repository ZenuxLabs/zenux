"""Unit tests for the model supply chain scanner.

Tool name: 06_model_supply_chain_scanner tests
OWASP coverage: LLM03, LLM04
MITRE mapping: mocked AML.T0010 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest

from tests.support import load_tool_module

supply = load_tool_module("06_model_supply_chain_scanner.py", "tool_06_supply")


class SupplyChainTests(unittest.TestCase):
    def test_pickle_magic_bytes_is_critical(self) -> None:
        finding = supply.analyze_artifact_bytes("/models/model.pkl", b"\x80\x04pickle-data", "https://models.example.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")

    def test_safetensors_returns_no_finding(self) -> None:
        finding = supply.analyze_artifact_bytes("/models/model.safetensors", b'{"\x00\x00safe', "https://models.example.com")
        self.assertIsNone(finding)

    def test_trust_remote_code_true_is_high(self) -> None:
        finding = supply.analyze_artifact_bytes(
            "/models/config.json",
            b'{"trust_remote_code": true, "architectures": ["Model"]}',
            "https://models.example.com",
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")

    def test_global_opcode_in_pickle_is_critical(self) -> None:
        finding = supply.analyze_artifact_bytes(
            "/models/model.pkl",
            b"\x80\x04cGLOBAL\nos\nsystem\n",
            "https://models.example.com",
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")


if __name__ == "__main__":
    unittest.main()

