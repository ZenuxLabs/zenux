"""Unit tests for the native toolkit finding schema.

Tool name: schema tests
OWASP coverage: LLM01-LLM10
MITRE mapping: mocked AML validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest

from lib.schema import build_finding, compute_toxicity


class SchemaTests(unittest.TestCase):
    def test_compute_toxicity_math_and_label_mapping(self) -> None:
        toxicity = compute_toxicity(25, 20, 15, 10)
        self.assertEqual(toxicity.overall, 72)
        self.assertEqual(toxicity.label, "high")

    def test_to_dict_round_trip_keeps_required_fields(self) -> None:
        finding = build_finding(
            tool_id="01",
            title="Exposed model list",
            severity="high",
            class_name="data_exfiltration",
            owasp_category="LLM02",
            mitre_atlas_technique="AML.T0007 - Reconnaissance",
            source="01_ai_infrastructure_recon",
            toxicity=compute_toxicity(15, 20, 10, 15),
            fixability="immediate",
            remediation_steps=["Add authentication.", "Scope the endpoint to operators only."],
            affected_target="api.example.com",
            evidence="x" * 1200,
        )

        payload = finding.to_dict()
        self.assertEqual(payload["riskScore"], payload["toxicity"]["overall"])
        self.assertEqual(payload["owaspCategory"], "LLM02")
        self.assertLessEqual(len(payload["evidence"]), 800)
        self.assertEqual(payload["status"], "new")


if __name__ == "__main__":
    unittest.main()
