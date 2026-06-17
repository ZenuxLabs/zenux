"""Unit tests for the model supply chain scanner.

Tool name: 06_model_supply_chain_scanner tests
OWASP coverage: LLM03, LLM04
MITRE mapping: mocked AML.T0010 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.

Scope note: Tool 06 owns HTTP-level *exposure* detection only — it reports that a
sensitive artifact type is reachable over HTTP, not what its contents contain.
Byte/content-level severity escalation (pickle opcode analysis such as GLOBAL/REDUCE,
``trust_remote_code`` parsing, compression-bypass detection) is the exclusive
responsibility of Tool 12 (``12_ml_model_static_scanner``) and is covered by
``test_12_ml_model_scanner.py``. These tests therefore assert exposure-level severities,
not content-level ones.
"""

from __future__ import annotations

import unittest

from tests.support import load_tool_module

supply = load_tool_module("06_model_supply_chain_scanner.py", "tool_06_supply")


class SupplyChainTests(unittest.TestCase):
    def test_pickle_magic_bytes_is_high(self) -> None:
        finding = supply.analyze_artifact_exposure(
            "/models/model.pkl", b"\x80\x04pickle-data", "https://models.example.com"
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.className, "supply_chain")

    def test_safetensors_returns_no_finding(self) -> None:
        finding = supply.analyze_artifact_exposure(
            "/models/model.safetensors", b'{"\x00\x00safe', "https://models.example.com"
        )
        self.assertIsNone(finding)

    def test_config_json_exposure_is_medium(self) -> None:
        finding = supply.analyze_artifact_exposure(
            "/models/config.json",
            b'{"trust_remote_code": true, "architectures": ["Model"]}',
            "https://models.example.com",
        )
        self.assertIsNotNone(finding)
        # Tool 06 reports HTTP reachability of the config file; the
        # trust_remote_code -> high escalation belongs to Tool 12.
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.className, "supply_chain")

    def test_pickle_with_global_opcode_is_exposed_as_high(self) -> None:
        # GLOBAL/REDUCE opcode -> critical escalation is Tool 12's responsibility.
        # At the exposure layer this is still a pickle artifact reachable over HTTP.
        finding = supply.analyze_artifact_exposure(
            "/models/model.pkl",
            b"\x80\x04cGLOBAL\nos\nsystem\n",
            "https://models.example.com",
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")


if __name__ == "__main__":
    unittest.main()
