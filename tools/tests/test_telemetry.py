"""Unit tests for OTEL telemetry helpers.

Tool name: telemetry tests
OWASP coverage: LLM01-LLM10
MITRE mapping: mocked observability validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import os
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.support import load_tool_module

telemetry = load_tool_module("lib/telemetry.py", "tool_lib_telemetry")


class TelemetryTests(unittest.TestCase):
    def test_scan_span_yields_none_when_tracer_missing(self) -> None:
        with patch.object(telemetry, "_tracer", None):
            with telemetry.scan_span("tool", "example.com", "01") as span:
                self.assertIsNone(span)

    def test_scan_span_sets_genai_attributes_with_mocked_tracer(self) -> None:
        span = Mock()

        @contextmanager
        def span_context(name: str):  # noqa: ANN202
            self.assertEqual(name, "invoke_agent scanner")
            yield span

        tracer = Mock()
        tracer.start_as_current_span.side_effect = span_context

        with patch.object(telemetry, "_tracer", tracer):
            with telemetry.scan_span("scanner", "target.example", "07") as active_span:
                self.assertIs(active_span, span)

        span.set_attribute.assert_any_call("gen_ai.agent.name", "scanner")
        span.set_attribute.assert_any_call("gen_ai.tool.type", "extension")
        span.set_attribute.assert_any_call("gen_ai.operation.name", "scan")
        span.set_attribute.assert_any_call("target.host", "target.example")
        span.set_attribute.assert_any_call("scan.tool_number", "07")

    def test_record_findings_noops_when_span_missing(self) -> None:
        telemetry.record_findings(None, [SimpleNamespace(severity="critical")], "scanner")

    def test_record_findings_sets_critical_and_high_counts(self) -> None:
        span = Mock()
        findings = [
            SimpleNamespace(severity="critical"),
            SimpleNamespace(severity="high"),
            SimpleNamespace(severity="medium"),
        ]

        telemetry.record_findings(span, findings, "scanner")

        span.set_attribute.assert_any_call("scan.findings_count", 3)
        span.set_attribute.assert_any_call("scan.findings_critical", 1)
        span.set_attribute.assert_any_call("scan.findings_high", 1)
        span.set_attribute.assert_any_call("gen_ai.security.threat_detected", True)

    def test_setup_telemetry_returns_none_when_endpoint_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch.object(telemetry, "_OTEL_AVAILABLE", True):
            self.assertIsNone(telemetry.setup_telemetry())


if __name__ == "__main__":
    unittest.main()
