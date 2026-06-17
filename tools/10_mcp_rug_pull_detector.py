"""Zenux Scan Toolkit: MCP rug-pull detector.

Tool name: 10_mcp_rug_pull_detector
OWASP coverage: LLM07
MITRE mapping: AML.T0051 - Prompt Injection
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import requests

from lib.reporter import push_findings
from lib.schema import MCPRugPullFinding, Severity, _generate_finding_id, compute_toxicity
from lib.target import validate_target

TOOL_ID = "10"
SOURCE = "10_mcp_rug_pull_detector"
MITRE_TECHNIQUE = "AML.T0051 - Prompt Injection"


def fetch_tool_manifest(base_url: str, timeout: int = 10) -> dict[str, dict[str, Any]]:
    """Fetch the current MCP tool manifest keyed by tool name."""

    response = requests.get(f"{base_url.rstrip('/')}/tools", timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    tools = payload.get("tools", [])
    if not isinstance(tools, list):
        return {}
    return {
        tool["name"]: tool
        for tool in tools
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    }


def check_etdi(tool_def: dict[str, Any]) -> bool:
    """Return True when the tool definition carries ETDI-style integrity metadata."""

    return "tool_version" in tool_def or "definition_hash" in tool_def


def probe_tool_shadowing(base_url: str, known_tools: list[str], timeout: int = 10) -> str | None:
    """Probe whether the server accepts a shadowed tool invocation body."""

    if len(known_tools) < 2:
        return None

    payload = {"tool": known_tools[0], "arguments": {}, "_shadow_test": known_tools[1]}
    try:
        response = requests.post(f"{base_url.rstrip('/')}/call", json=payload, timeout=timeout)
        if response.status_code == 200 and known_tools[1] in response.text:
            return known_tools[1]
    except Exception:
        return None
    return None


def _remediation_steps(mutation_type: str) -> list[str]:
    if mutation_type == "unsigned":
        return [
            "Add ETDI-style tool_version or definition_hash metadata to every MCP tool definition.",
            "Require clients to pin approved tool-definition hashes before allowing execution.",
            "Alert operators when tool metadata arrives unsigned or changes unexpectedly.",
        ]
    return [
        "Pin and verify MCP tool definitions before execution approval.",
        "Block post-approval tool mutations until an operator re-approves the changed definition.",
        "Require ETDI-style signed tool metadata for every server-exposed tool.",
    ]


def _build_finding(
    *,
    title: str,
    severity: Severity,
    target: str,
    mutation_type: str,
    original_definition: dict[str, Any],
    mutated_definition: dict[str, Any],
    etdi_signed: bool,
    evidence: str,
) -> MCPRugPullFinding:
    toxicity_inputs = {
        "critical": (25, 25, 25, 25),
        "high": (20, 15, 20, 15),
        "medium": (10, 10, 10, 10),
        "low": (5, 5, 5, 5),
    }[severity]
    return MCPRugPullFinding(
        id=_generate_finding_id(TOOL_ID),
        title=title,
        severity=severity,
        className="mcp_abuse",
        owaspCategory="LLM07",
        mitreAtlasTechnique=MITRE_TECHNIQUE,
        source=SOURCE,
        toxicity=compute_toxicity(*toxicity_inputs),
        fixability="immediate" if severity == "critical" else "short_term",
        remediationSteps=_remediation_steps(mutation_type),
        affectedTarget=target,
        evidence=evidence,
        mutation_type=mutation_type,
        original_definition=original_definition,
        mutated_definition=mutated_definition,
        etdi_signed=etdi_signed,
    )


def run_scan(target: str) -> list[MCPRugPullFinding]:
    normalized_host = validate_target(target)
    base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    findings: list[MCPRugPullFinding] = []

    try:
        manifest_t0 = fetch_tool_manifest(base_url)
    except Exception:
        return findings

    time.sleep(5)

    try:
        manifest_t1 = fetch_tool_manifest(base_url)
    except Exception:
        return findings

    all_tools = set(manifest_t0) | set(manifest_t1)
    for name in sorted(all_tools):
        if name not in manifest_t0:
            findings.append(
                _build_finding(
                    title=f"MCP Tool Added Post-Connection: {name}",
                    severity="critical",
                    target=normalized_host,
                    mutation_type="added",
                    original_definition={},
                    mutated_definition=manifest_t1[name],
                    etdi_signed=check_etdi(manifest_t1[name]),
                    evidence=json.dumps({"before": {}, "after": manifest_t1[name]}, sort_keys=True),
                )
            )
        elif name not in manifest_t1:
            findings.append(
                _build_finding(
                    title=f"MCP Tool Removed Post-Connection: {name}",
                    severity="high",
                    target=normalized_host,
                    mutation_type="removed",
                    original_definition=manifest_t0[name],
                    mutated_definition={},
                    etdi_signed=False,
                    evidence=json.dumps({"before": manifest_t0[name], "after": {}}, sort_keys=True),
                )
            )
        elif manifest_t0[name] != manifest_t1[name]:
            findings.append(
                _build_finding(
                    title=f"MCP Tool Definition Mutated: {name}",
                    severity="critical",
                    target=normalized_host,
                    mutation_type="modified",
                    original_definition=manifest_t0[name],
                    mutated_definition=manifest_t1[name],
                    etdi_signed=check_etdi(manifest_t1[name]),
                    evidence=json.dumps({"before": manifest_t0[name], "after": manifest_t1[name]}, sort_keys=True),
                )
            )

    tool_names = sorted(manifest_t1.keys())
    shadowed = probe_tool_shadowing(base_url, tool_names)
    if shadowed:
        findings.append(
            _build_finding(
                title=f"MCP Tool Shadowing Confirmed (CVE-2025-6514): {shadowed}",
                severity="critical",
                target=normalized_host,
                mutation_type="shadowed",
                original_definition=manifest_t1.get(shadowed, {}),
                mutated_definition={},
                etdi_signed=check_etdi(manifest_t1.get(shadowed, {})),
                evidence=json.dumps({"shadowed_tool": shadowed, "tool_count": len(tool_names)}, sort_keys=True),
            )
        )

    for name, definition in sorted(manifest_t1.items()):
        if check_etdi(definition):
            continue
        findings.append(
            _build_finding(
                title=f"MCP Tool Not ETDI-Signed: {name}",
                severity="medium",
                target=normalized_host,
                mutation_type="unsigned",
                original_definition=definition,
                mutated_definition={},
                etdi_signed=False,
                evidence=json.dumps(definition, sort_keys=True),
            )
        )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect MCP tool-definition mutation, shadowing, and ETDI gaps.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", choices=["json", "table"], default="json")
    parser.add_argument("--push-github", action="store_true")
    parser.add_argument("--github-token")
    args = parser.parse_args()

    findings = run_scan(args.target)
    payload = [finding.to_dict() for finding in findings]
    if args.output == "json":
        print(json.dumps(payload, indent=2))
    else:
        for finding in findings:
            print(f"{finding.severity.upper():8} {finding.mutation_type:9} {finding.title}")

    if args.push_github and args.github_token:
        push_findings(findings, args.github_token)


if __name__ == "__main__":
    main()
