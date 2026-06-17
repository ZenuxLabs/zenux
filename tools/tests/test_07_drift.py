"""Unit tests for the behavioral drift detector.

Tool name: 07_behavioral_drift_detector tests
OWASP coverage: LLM04, LLM08
MITRE mapping: mocked AML.T0051.001 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.support import load_tool_module

drift = load_tool_module("07_behavioral_drift_detector.py", "tool_07_drift")


class DriftTests(unittest.TestCase):
    def test_token_overlap_similarity_handles_identical_disjoint_and_partial_strings(self) -> None:
        self.assertEqual(drift.token_overlap_similarity("alpha beta", "alpha beta"), 1.0)
        self.assertEqual(drift.token_overlap_similarity("alpha beta", "gamma delta"), 0.0)
        self.assertEqual(drift.token_overlap_similarity("alpha beta", "alpha gamma"), 0.5)

    def test_compute_drift_score_handles_zero_half_and_full_drift(self) -> None:
        self.assertEqual(drift.compute_drift_score(["alpha beta"], ["alpha beta"]), 0.0)
        self.assertEqual(drift.compute_drift_score(["alpha beta"], ["alpha gamma"]), 0.5)
        self.assertEqual(drift.compute_drift_score(["alpha beta"], ["gamma delta"]), 1.0)

    def test_save_and_load_baseline_round_trip(self) -> None:
        probes = [{"question": "What is 2+2?", "response": "4", "elapsed": 1.0}]

        with tempfile.TemporaryDirectory() as tmpdir, patch.object(drift, "BASELINE_DIR", tmpdir):
            drift.save_baseline("https://api.example.com", probes)
            loaded = drift.load_baseline("https://api.example.com")

        self.assertEqual(loaded, probes)

    def test_four_of_five_answer_changes_is_critical(self) -> None:
        baseline = [{"text": "4", "elapsed": 1.0}, {"text": "Paris", "elapsed": 1.0}, {"text": "blue", "elapsed": 1.0}, {"text": "Shakespeare", "elapsed": 1.0}, {"text": "HyperText Transfer Protocol", "elapsed": 1.0}]
        poisoned = [{"text": "5", "elapsed": 1.0}, {"text": "Berlin", "elapsed": 1.0}, {"text": "green", "elapsed": 1.0}, {"text": "Isaac Newton", "elapsed": 1.0}, {"text": "HyperText Transfer Protocol", "elapsed": 1.0}]
        recovery = baseline
        findings = drift.evaluate_drift_results(baseline, poisoned, recovery, "https://api.example.com")
        self.assertTrue(any(f.className == "indirect_injection" and f.severity == "critical" for f in findings))

    def test_zero_changes_returns_no_finding(self) -> None:
        baseline = [
            {"text": "4", "elapsed": 1.0},
            {"text": "Paris", "elapsed": 1.0},
            {"text": "blue", "elapsed": 1.0},
            {"text": "Shakespeare", "elapsed": 1.0},
            {"text": "HyperText Transfer Protocol", "elapsed": 1.0},
        ]
        poisoned = list(baseline)
        recovery = list(baseline)
        findings = drift.evaluate_drift_results(baseline, poisoned, recovery, "https://api.example.com")
        self.assertEqual(findings, [])

    def test_persistent_poisoning_is_critical(self) -> None:
        baseline = [{"text": "4", "elapsed": 1.0}, {"text": "Paris", "elapsed": 1.0}, {"text": "blue", "elapsed": 1.0}, {"text": "Shakespeare", "elapsed": 1.0}, {"text": "HyperText Transfer Protocol", "elapsed": 1.0}]
        poisoned = baseline
        recovery = [{"text": "5", "elapsed": 1.0}, {"text": "Berlin", "elapsed": 1.0}, {"text": "green", "elapsed": 1.0}, {"text": "Newton", "elapsed": 1.0}, {"text": "Hostile Takeover Protocol", "elapsed": 1.0}]
        findings = drift.evaluate_drift_results(baseline, poisoned, recovery, "https://api.example.com")
        self.assertTrue(any(f.className == "model_poisoning" and f.severity == "critical" for f in findings))

    def test_drift_threshold_flag_is_parsed(self) -> None:
        parser = drift.build_parser()
        args = parser.parse_args(
            [
                "--endpoint",
                "https://api.example.com",
                "--continuous",
                "--interval",
                "120",
                "--drift-threshold",
                "0.4",
                "--critical-threshold",
                "0.7",
            ]
        )

        self.assertTrue(args.continuous)
        self.assertEqual(args.interval, 120)
        self.assertEqual(args.drift_threshold, 0.4)
        self.assertEqual(args.critical_threshold, 0.7)

    @patch.object(drift, "time")
    @patch.object(drift, "push_finding")
    @patch.object(drift, "save_baseline")
    @patch.object(drift, "load_baseline")
    @patch.object(drift, "run_probes")
    def test_continuous_mode_exits_after_keyboard_interrupt(
        self,
        mock_run_probes: unittest.mock.Mock,
        mock_load_baseline: unittest.mock.Mock,
        mock_save_baseline: unittest.mock.Mock,
        mock_push_finding: unittest.mock.Mock,
        mock_time: unittest.mock.Mock,
    ) -> None:
        baseline = [{"question": "What is 2+2?", "response": "4", "elapsed": 1.0}]
        current = [{"question": "What is 2+2?", "response": "5", "elapsed": 1.0}]
        mock_load_baseline.return_value = None
        mock_run_probes.side_effect = [baseline, current, KeyboardInterrupt]
        mock_time.strftime.return_value = "2026-03-14T00:00:00Z"
        mock_time.sleep.return_value = None

        args = SimpleNamespace(
            auth_header=None,
            interval=1,
            drift_threshold=0.3,
            critical_threshold=0.6,
            push_github=True,
            github_token="token",
        )

        drift.run_continuous("https://api.example.com", args)

        self.assertEqual(mock_run_probes.call_count, 3)
        self.assertEqual(mock_save_baseline.call_count, 2)
        mock_push_finding.assert_called_once()
        finding = mock_push_finding.call_args.args[0]
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.extra["monitoring_mode"], "continuous")


if __name__ == "__main__":
    unittest.main()
