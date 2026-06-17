"""OpenTelemetry instrumentation for Zenux scan tools.

Uses gen_ai.* semantic conventions (OTEL GenAI spec, 2025).
Exports to Arize Phoenix via OTLP HTTP.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace import Status, StatusCode

    _OTEL_AVAILABLE = True
except ImportError:
    trace = None  # type: ignore[assignment]
    OTLPSpanExporter = None  # type: ignore[assignment]
    Resource = None  # type: ignore[assignment]
    TracerProvider = None  # type: ignore[assignment]
    BatchSpanProcessor = None  # type: ignore[assignment]
    Status = None  # type: ignore[assignment]
    StatusCode = None  # type: ignore[assignment]
    _OTEL_AVAILABLE = False


def setup_telemetry() -> Optional[object]:
    """Initialize OTEL tracer. Returns tracer or None if OTEL not available/configured."""

    if not _OTEL_AVAILABLE:
        return None

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return None

    current_provider = trace.get_tracer_provider()
    if current_provider.__class__.__name__ != "ProxyTracerProvider":
        return trace.get_tracer("gal.security.scanner")

    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", "zenux"),
            "service.version": "1.0.0",
        }
    )

    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    return trace.get_tracer("gal.security.scanner")


_tracer = setup_telemetry()


@contextmanager
def scan_span(tool_name: str, target: str, tool_number: str) -> Iterator[Any]:
    """Wrap a scan tool run in an OTEL span using GenAI semantic conventions."""

    if _tracer is None:
        yield None
        return

    with _tracer.start_as_current_span(f"invoke_agent {tool_name}") as span:
        span.set_attribute("gen_ai.agent.name", tool_name)
        span.set_attribute("gen_ai.tool.type", "extension")
        span.set_attribute("gen_ai.operation.name", "scan")
        span.set_attribute("target.host", target)
        span.set_attribute("scan.tool_number", tool_number)
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            if Status is not None and StatusCode is not None:
                span.set_status(Status(status_code=StatusCode.ERROR, description=str(exc)))
            raise


def record_findings(span: Any, findings: list[Any], tool_name: str) -> None:
    """Record finding count and severity distribution on the active span."""

    if span is None:
        return

    span.set_attribute("gen_ai.agent.name", tool_name)
    span.set_attribute("scan.findings_count", len(findings))
    critical = sum(1 for finding in findings if getattr(finding, "severity", "") == "critical")
    high = sum(1 for finding in findings if getattr(finding, "severity", "") == "high")
    span.set_attribute("scan.findings_critical", critical)
    span.set_attribute("scan.findings_high", high)
    if critical > 0:
        span.set_attribute("gen_ai.security.threat_detected", True)
