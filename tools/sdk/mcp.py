"""MCP boundary helpers for Zenux runtime reporting."""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Mapping, Sequence
from functools import wraps
from typing import Any

from lib.schema import Finding, build_finding, compute_toxicity

from .client import ZenuxClient, PolicyViolationError
from .redaction import normalize_text, redact_text, truncate_text
from .session import AgentSession


_REDACTED_MARKER_RE = re.compile(r"\[REDACTED:([^\]]+)\]")


def redact_mcp_payload(value: Any, *, max_depth: int = 6) -> Any:
    """Recursively redact an MCP payload while preserving structure."""

    if max_depth <= 0:
        return "[REDACTED:DEPTH_LIMIT]"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return truncate_text(redact_text(value), 800)

    if isinstance(value, (bytes, bytearray)):
        return truncate_text(redact_text(value.decode("utf-8", errors="replace")), 800)

    if isinstance(value, Finding):
        return redact_mcp_payload(value.to_dict(), max_depth=max_depth - 1)

    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        try:
            return redact_mcp_payload(value.to_dict(), max_depth=max_depth - 1)
        except Exception:
            pass

    if isinstance(value, Mapping):
        return {str(key): redact_mcp_payload(entry, max_depth=max_depth - 1) for key, entry in value.items()}

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_mcp_payload(entry, max_depth=max_depth - 1) for entry in value]

    if hasattr(value, "__dict__"):
        try:
            return redact_mcp_payload(vars(value), max_depth=max_depth - 1)
        except Exception:
            pass

    return truncate_text(redact_text(str(value)), 240)


def _safe_snippet(value: Any, max_length: int = 600) -> str:
    return normalize_text(redact_mcp_payload(value), max_length)


def _marker_labels(text: str) -> set[str]:
    return {marker.strip().upper() for marker in _REDACTED_MARKER_RE.findall(text)}


def _build_finding(
    *,
    server_name: str,
    tool_name: str,
    source: str,
    severity: str,
    class_name: str,
    title: str,
    owasp_category: str,
    remediation_steps: list[str],
    evidence: str,
) -> Finding:
    mitre_atlas_technique = (
        "AML.T0040 - ML Model Access" if class_name == "credential_theft" else "AML.T0051 - Prompt Injection"
    )
    return build_finding(
        tool_id="MCP",
        title=title,
        severity=severity,  # type: ignore[arg-type]
        class_name=class_name,  # type: ignore[arg-type]
        owasp_category=owasp_category,
        mitre_atlas_technique=mitre_atlas_technique,
        source=source,
        toxicity=compute_toxicity(30 if class_name == "credential_theft" else 15, 20, 20, 25),
        fixability="immediate" if class_name == "credential_theft" else "short_term",
        remediation_steps=remediation_steps,
        affected_target=f"{server_name}:{tool_name}",
        evidence=evidence,
    )


def _scan_redacted_text(
    redacted_text: str,
    *,
    server_name: str,
    tool_name: str,
    source: str,
) -> list[Finding]:
    markers = _marker_labels(redacted_text)
    findings: list[Finding] = []

    if "PROMPT_INJECTION" in markers:
        findings.append(
            _build_finding(
                server_name=server_name,
                tool_name=tool_name,
                source=source,
                severity="high",
                class_name="prompt_injection",
                title=f"MCP tool response contained prompt injection: {server_name}/{tool_name}",
                owasp_category="LLM07",
                remediation_steps=[
                    "Treat the upstream MCP server output as untrusted.",
                    "Strip or quarantine prompt-injection payloads before they reach the caller.",
                    "Review the server contract and tighten output allowlists where possible.",
                ],
                evidence=redacted_text,
            )
        )

    if any(marker != "PROMPT_INJECTION" for marker in markers):
        findings.append(
            _build_finding(
                server_name=server_name,
                tool_name=tool_name,
                source=source,
                severity="critical",
                class_name="credential_theft",
                title=f"MCP tool response exposed credential material: {server_name}/{tool_name}",
                owasp_category="LLM02",
                remediation_steps=[
                    "Do not return raw secret material to the caller.",
                    "Rotate any credential that was exposed by the tool response.",
                    "Review the MCP server's output contract and secret handling path.",
                ],
                evidence=redacted_text,
            )
        )

    return findings


def monitor_mcp(
    subject: ZenuxClient | AgentSession,
    *,
    server_name: str,
    tool_name: str | None = None,
    source: str = "mcp-proxy",
    asset_id: str | None = None,
    policy_hook: str | None = None,
    enforce_policy: bool = False,
    report_findings: bool = True,
    redact_output: bool = True,
):
    """Decorate an MCP transport function with safe request/response telemetry."""

    session = subject if isinstance(subject, AgentSession) else None
    client = subject.client if isinstance(subject, AgentSession) else subject
    monitor_tool_name = tool_name or "tool"
    monitor_source = source or "mcp-proxy"
    target_id = asset_id or server_name

    def _finalize_result(
        *,
        active_session: AgentSession,
        started_here: bool,
        request_snippet: str,
        result: Any,
    ) -> Any:
        redacted_result = redact_mcp_payload(result) if redact_output else result
        response_snippet = _safe_snippet(redacted_result)
        findings = _scan_redacted_text(
            response_snippet,
            server_name=server_name,
            tool_name=monitor_tool_name,
            source=monitor_source,
        )

        if findings and report_findings:
            active_session.report_findings(findings, target_id=target_id)

        policy_result = None
        if policy_hook:
            policy_result = client.evaluate_policy(
                hook=policy_hook,
                event={
                    "serverName": server_name,
                    "toolName": monitor_tool_name,
                    "requestSnippet": request_snippet,
                    "responseSnippet": response_snippet,
                    "findingCount": len(findings),
                },
                actor_id=active_session.agent_id,
                requested_by=active_session.agent_id,
                asset_id=asset_id or server_name,
            )
            active_session.log_event(
                action="mcp.policy.evaluated",
                summary=f"Policy evaluated for {server_name}/{monitor_tool_name}.",
                target_type="mcp_server",
                target_id=target_id,
                metadata={
                    "serverName": server_name,
                    "toolName": monitor_tool_name,
                    "decision": (policy_result or {}).get("overallDecision", "unknown"),
                },
            )
            if enforce_policy and policy_result and policy_result.get("overallDecision") == "block":
                active_session.log_event(
                    action="mcp.tool_call.blocked",
                    summary=f"Tool call blocked by policy: {server_name}/{monitor_tool_name}.",
                    target_type="mcp_server",
                    target_id=target_id,
                    metadata={
                        "serverName": server_name,
                        "toolName": monitor_tool_name,
                        "decision": policy_result.get("overallDecision"),
                        "findingCount": len(findings),
                    },
                )
                if started_here:
                    active_session.__exit__(None, None, None)
                raise PolicyViolationError(
                    f"Policy blocked monitored MCP tool call: {server_name}/{monitor_tool_name}",
                    policy_result=policy_result,
                )

        active_session.log_event(
            action="mcp.tool_call.completed",
            summary=f"MCP tool response captured: {server_name}/{monitor_tool_name}.",
            target_type="mcp_server",
            target_id=target_id,
            metadata={
                "serverName": server_name,
                "toolName": monitor_tool_name,
                "requestSnippet": request_snippet,
                "responseSnippet": response_snippet,
                "findingCount": len(findings),
                "redactedOutput": bool(findings) and redact_output,
            },
        )

        if started_here:
            active_session.__exit__(None, None, None)

        return redacted_result if findings and redact_output else result

    def decorator(fn: Callable[..., Any]):
        if inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any):
                active_session = session or client.session(source=monitor_source)
                started_here = session is None
                request_snippet = _safe_snippet({"args": args, "kwargs": kwargs})

                if started_here:
                    active_session.__enter__()

                active_session.log_event(
                    action="mcp.tool_call.started",
                    summary=f"MCP tool call started: {server_name}/{monitor_tool_name}.",
                    target_type="mcp_server",
                    target_id=target_id,
                    metadata={
                        "serverName": server_name,
                        "toolName": monitor_tool_name,
                        "source": monitor_source,
                        "requestSnippet": request_snippet,
                    },
                )

                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    active_session.log_event(
                        action="mcp.tool_call.failed",
                        summary=f"MCP tool call failed: {server_name}/{monitor_tool_name}.",
                        target_type="mcp_server",
                        target_id=target_id,
                        metadata={
                            "serverName": server_name,
                            "toolName": monitor_tool_name,
                            "error": truncate_text(redact_text(str(exc)), 240),
                            "errorType": type(exc).__name__,
                        },
                    )
                    if started_here:
                        active_session.__exit__(type(exc), exc, exc.__traceback__)
                    raise

                return _finalize_result(
                    active_session=active_session,
                    started_here=started_here,
                    request_snippet=request_snippet,
                    result=result,
                )

            return async_wrapper

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            active_session = session or client.session(source=monitor_source)
            started_here = session is None
            request_snippet = _safe_snippet({"args": args, "kwargs": kwargs})

            if started_here:
                active_session.__enter__()

            active_session.log_event(
                action="mcp.tool_call.started",
                summary=f"MCP tool call started: {server_name}/{monitor_tool_name}.",
                target_type="mcp_server",
                target_id=target_id,
                metadata={
                    "serverName": server_name,
                    "toolName": monitor_tool_name,
                    "source": monitor_source,
                    "requestSnippet": request_snippet,
                },
            )

            try:
                result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                active_session.log_event(
                    action="mcp.tool_call.failed",
                    summary=f"MCP tool call failed: {server_name}/{monitor_tool_name}.",
                    target_type="mcp_server",
                    target_id=target_id,
                    metadata={
                        "serverName": server_name,
                        "toolName": monitor_tool_name,
                        "error": truncate_text(redact_text(str(exc)), 240),
                        "errorType": type(exc).__name__,
                    },
                )
                if started_here:
                    active_session.__exit__(type(exc), exc, exc.__traceback__)
                raise

            return _finalize_result(
                active_session=active_session,
                started_here=started_here,
                request_snippet=request_snippet,
                result=result,
            )

        return wrapper

    return decorator
