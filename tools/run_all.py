"""Zenux Scan Toolkit: unified orchestrator.

Tool name: run_all
OWASP coverage: LLM01-LLM10
MITRE mapping: multiple AML techniques depending on tool output
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

from lib.reporter import push_finding
from lib.schema import Finding
from lib.telemetry import record_findings, scan_span
from sdk.client import ZenuxClient

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_module(filename: str, module_name: str) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, TOOLS_DIR / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dedupe(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.title, finding.affectedTarget)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped


def _format_table(findings: list[Finding]) -> str:
    title_width = 47
    lines = [
        "┌" + "─" * 49 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 8 + "┐",
        "│ Finding                                         │ Severity │ OWASP    │ Score  │",
        "├" + "─" * 49 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 8 + "┤",
    ]
    for finding in findings:
        title = finding.title[:title_width].ljust(title_width)
        severity = finding.severity.upper().ljust(8)
        owasp = finding.owaspCategory.ljust(8)
        score = str(finding.riskScore).ljust(6)
        lines.append(f"│ {title} │ {severity} │ {owasp} │ {score} │")
    lines.append("└" + "─" * 49 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 8 + "┘")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the full Zenux scan toolkit.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--auth-header")
    parser.add_argument("--github-token")
    parser.add_argument("--push-github", action="store_true")
    parser.add_argument("--output", default="results")
    parser.add_argument("--ingest-endpoint", default="/api/documents")
    parser.add_argument("--query-endpoint", default="/api/query")
    parser.add_argument("--black-box", action="store_true")
    parser.add_argument("--tools")
    args = parser.parse_args()

    runners: list[tuple[str, str, Callable[[Any], dict[str, Any]]]] = [
        ("01_ai_infrastructure_recon.py", "scan_target", lambda parsed: {"target": parsed.target}),
        (
            "02_prompt_injection_scanner.py",
            "scan_endpoint",
            lambda parsed: {"endpoint": parsed.endpoint, "auth_header": parsed.auth_header},
        ),
        (
            "03_rag_poisoning_probe.py",
            "scan_endpoint",
            lambda parsed: {
                "endpoint": parsed.endpoint,
                "ingest_endpoint": parsed.ingest_endpoint,
                "query_endpoint": parsed.query_endpoint,
                "auth_header": parsed.auth_header,
                "black_box": parsed.black_box,
            },
        ),
        (
            "04_agent_scope_tester.py",
            "scan_endpoint",
            lambda parsed: {"endpoint": parsed.endpoint, "auth_header": parsed.auth_header},
        ),
        ("05_mcp_exploit_mapper.py", "scan_target", lambda parsed: {"target": parsed.target, "auth_header": parsed.auth_header}),
        ("06_model_supply_chain_scanner.py", "scan_target", lambda parsed: {"target": parsed.target}),
        (
            "07_behavioral_drift_detector.py",
            "scan_endpoint",
            lambda parsed: {"endpoint": parsed.endpoint, "auth_header": parsed.auth_header},
        ),
        (
            "08_unbounded_consumption_prober.py",
            "scan_endpoint",
            lambda parsed: {"endpoint": parsed.endpoint, "auth_header": parsed.auth_header},
        ),
        (
            "09_system_prompt_leakage_prober.py",
            "scan_endpoint",
            lambda parsed: {"endpoint": parsed.endpoint, "auth_header": parsed.auth_header},
        ),
        ("10_mcp_rug_pull_detector.py", "run_scan", lambda parsed: {"target": parsed.target}),
        ("11_litellm_policy_probe.py", "scan_target", lambda parsed: {"target": parsed.target, "auth_header": parsed.auth_header}),
        ("12_ml_model_static_scanner.py", "scan_target", lambda parsed: {"target": parsed.target}),
        ("13_llmjacking_credential_detector.py", "scan_target", lambda parsed: {"target": parsed.target, "auth_header": parsed.auth_header}),
    ]

    requested_tools = {entry.strip() for entry in (args.tools or "").split(",") if entry.strip()}

    client = ZenuxClient(source='run_all')
    findings: list[Finding] = []
    with client.session(
        agent_id=os.environ.get("GAL_AGENT_ID")
        or os.environ.get("AGENT_ID")
        or os.environ.get("HOSTNAME")
        or 'run_all',
        repo=os.environ.get("GITHUB_REPOSITORY"),
        work_item_id=os.environ.get("GAL_WORK_ITEM_ID") or os.environ.get("WORK_ITEM_ID") or args.target,
        source='run_all',
    ) as session:
        session.log_event(
            action='agent.run.started',
            summary='Zenux Scan Toolkit orchestration started.',
            metadata={
                'target': args.target,
                'endpoint': args.endpoint,
                'toolFilter': ','.join(sorted(requested_tools)) if requested_tools else 'all',
            },
        )

        for index, (filename, function_name, kwargs_builder) in enumerate(runners, start=1):
            tool_id = filename.split('_', 1)[0]
            if requested_tools and tool_id not in requested_tools:
                continue
            tool_kwargs = kwargs_builder(args)
            tool_name = filename.removesuffix('.py')
            span_target = str(tool_kwargs.get('endpoint') or tool_kwargs.get('target') or args.target)
            try:
                with scan_span(tool_name=tool_name, target=span_target, tool_number=tool_id) as span:
                    module = _load_module(filename, f'native_scan_{index}')

                    @session.monitor(tool_name=tool_name, source='run_all')
                    def invoke_tool() -> list[Finding]:
                        return getattr(module, function_name)(**tool_kwargs)

                    tool_findings = invoke_tool()
                    record_findings(span, tool_findings, tool_name)
                    findings.extend(tool_findings)
            except Exception as exc:  # noqa: BLE001
                print(f'[warn] tool {filename} failed: {exc}', file=sys.stderr)

        deduped = _dedupe(findings)
        client.report_findings(deduped)
        session.log_event(
            action='agent.run.completed',
            summary='Zenux Scan Toolkit orchestration completed.',
            metadata={
                'findingCount': len(deduped),
                'criticalCount': sum(1 for finding in deduped if finding.severity == 'critical'),
                'highCount': sum(1 for finding in deduped if finding.severity == 'high'),
            },
        )

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / 'findings.json').write_text(
        json.dumps([finding.to_dict() for finding in deduped], indent=2),
        encoding='utf-8',
    )

    print(_format_table(deduped))
    severities = {level: sum(1 for finding in deduped if finding.severity == level) for level in ('critical', 'high', 'medium', 'low')}
    print(
        f"Total: {severities['critical']} critical, {severities['high']} high, "
        f"{severities['medium']} medium, {severities['low']} low"
    )

    if args.push_github and args.github_token:
        pushed = 0
        for finding in deduped:
            if push_finding(finding, args.github_token):
                pushed += 1
                time.sleep(1)
        if pushed:
            print(f'Pushed {pushed} findings to GitHub')


if __name__ == "__main__":
    main()
