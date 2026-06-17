"""Zenux Scan Toolkit: AI infrastructure recon.

Tool name: 01_ai_infrastructure_recon
OWASP coverage: LLM03, LLM07
MITRE mapping: AML.T0007 - Reconnaissance
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from lib.http import async_probe
from lib.kali import nmap_script, nmap_service_scan, parse_nmap_open_ports
from lib.reporter import push_findings
from lib.schema import Finding, build_finding, compute_toxicity
from lib.target import validate_target

TOOL_ID = "01"
SOURCE = "01_ai_infrastructure_recon"
MITRE_TECHNIQUE = "AML.T0007 - Reconnaissance"
AI_PATHS = [
    "/",
    "/health",
    "/api/tags",
    "/api/show",
    "/api/ps",
    "/api/version",
    "/v1/models",
    "/v1/files",
    "/v1/fine-tunes",
    "/v1/assistants",
    "/v1/engines",
    "/openai/deployments",
    "/v2/models",
    "/lm-studio/v1/models",
    "/sdapi/v1/options",
    "/api/health",
    "/metrics",
    "/ready",
    "/readyz",
    "/livez",
    "/info",
    "/pipeline_tag",
    "/models",
    "/model",
    "/docs",
    "/swagger",
    "/.well-known/ai-plugin.json",
    "/openapi.json",
]
VECTOR_DB_PORTS = {
    "chroma": (8000, "/api/v1/collections"),
    "weaviate": (8080, "/v1/.well-known/openid-configuration"),
    "qdrant": (6333, "/collections"),
    "milvus": (9091, "/healthz"),
}


def classify_stack(response: dict[str, Any]) -> str | None:
    headers = {str(key).lower(): str(value).lower() for key, value in response.get("headers", {}).items()}
    body = response.get("body_snippet", "")
    body_text = body if isinstance(body, str) else json.dumps(body)
    lowered = body_text.lower()

    if '"object": "list"' in lowered or '"object":"list"' in lowered:
        return "OpenAI-compatible"
    if "ollama" in lowered or '"models": [{"name"' in lowered or '"models":[{"name"' in lowered:
        return "Ollama"
    if "vllm" in headers.get("server", ""):
        return "vLLM"
    if '"endpoints"' in lowered:
        return "HuggingFace Inference"
    if "x-amzn-requestid" in headers:
        return "Bedrock"
    if '"type": "message"' in lowered or '"type":"message"' in lowered:
        return "Anthropic-compatible"
    return None


def _escalate(severity: str) -> str:
    order = ["low", "medium", "high", "critical"]
    try:
        return order[min(order.index(severity) + 1, len(order) - 1)]
    except ValueError:
        return severity


def _build_finding(
    *,
    title: str,
    severity: str,
    class_name: str,
    owasp_category: str,
    affected_target: str,
    evidence: str,
) -> Finding:
    return build_finding(
        tool_id=TOOL_ID,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        class_name=class_name,  # type: ignore[arg-type]
        owasp_category=owasp_category,
        mitre_atlas_technique=MITRE_TECHNIQUE,
        source=SOURCE,
        toxicity=compute_toxicity(
            15 if severity in {"medium", "high"} else 25,
            25 if severity == "critical" else 20 if severity == "high" else 10,
            20 if class_name == "supply_chain" else 10,
            20 if severity == "critical" else 15 if severity == "high" else 10,
        ),
        fixability="immediate" if severity in {"high", "critical"} else "short_term",
        remediation_steps=[
            "Put the exposed endpoint behind authentication and operator-only network policy.",
            "Remove unauthenticated metadata, model, or metrics routes from the public edge.",
            "Review the discovered AI stack for least-privilege deployment defaults.",
        ],
        affected_target=affected_target,
        evidence=evidence,
    )


def analyze_discovery_response(
    url: str,
    response: dict[str, Any],
    unauthenticated: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    if response.get("status") != 200:
        return findings

    parsed = urlparse(url)
    path = parsed.path
    stack = classify_stack(response) or "unknown"
    evidence = f"{stack} response on {path}: {response.get('body_snippet', '')}"

    severity = "high"
    if path == "/api/show":
        if "system" in evidence.lower() or "prompt" in evidence.lower():
            return [
                _build_finding(
                    title=f"{stack} model config exposed with prompt-bearing metadata",
                    severity="critical",
                    class_name="supply_chain",
                    owasp_category="LLM07",
                    affected_target=parsed.netloc,
                    evidence=evidence,
                )
            ]
        severity = "high"
        findings.append(
            _build_finding(
                title=f"{stack} model configuration exposed at /api/show",
                severity=severity,
                class_name="data_exfiltration",
                owasp_category="LLM07",
                affected_target=parsed.netloc,
                evidence=evidence,
            )
        )
    elif path in {"/v1/models", "/models", "/api/tags", "/api/ps", "/v2/models", "/lm-studio/v1/models"}:
        findings.append(
            _build_finding(
                title=f"Unauthenticated {stack} model inventory exposed at {path}",
                severity="high",
                class_name="data_exfiltration",
                owasp_category="LLM02",
                affected_target=parsed.netloc,
                evidence=evidence,
            )
        )
    elif path in {"/v1/files", "/v1/fine-tunes"}:
        findings.append(
            _build_finding(
                title=f"Training or file inventory exposed at {path}",
                severity="critical",
                class_name="supply_chain",
                owasp_category="LLM03",
                affected_target=parsed.netloc,
                evidence=evidence,
            )
        )
    elif path in {"/metrics", "/ready", "/readyz", "/livez"}:
        findings.append(
            _build_finding(
                title=f"Operational metrics exposed at {path}",
                severity="medium",
                class_name="data_exfiltration",
                owasp_category="LLM02",
                affected_target=parsed.netloc,
                evidence=evidence,
            )
        )

    if unauthenticated:
        for finding in findings:
            finding.severity = _escalate(finding.severity)  # type: ignore[assignment]
            finding.toxicity = compute_toxicity(
                finding.toxicity.accessLevel,
                finding.toxicity.dataExposure,
                min(25, finding.toxicity.lateralMovement + 5),
                min(25, finding.toxicity.exploitMaturity + 5),
            )
            finding.riskScore = finding.toxicity.overall

    return findings


def check_vector_db_auth(host: str, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []

    try:
        response = session.get(f"http://{host}:{VECTOR_DB_PORTS['chroma'][0]}{VECTOR_DB_PORTS['chroma'][1]}", timeout=timeout)
        if response.status_code == 200:
            findings.append(
                _build_finding(
                    title="Chroma Vector DB Unauthenticated",
                    severity="critical",
                    class_name="data_exfiltration",
                    owasp_category="LLM08",
                    affected_target=f"{host}:{VECTOR_DB_PORTS['chroma'][0]}",
                    evidence="Chroma API accessible without authentication at /api/v1/collections.",
                )
            )
    except Exception:
        pass

    try:
        oidc = session.get(f"http://{host}:{VECTOR_DB_PORTS['weaviate'][0]}{VECTOR_DB_PORTS['weaviate'][1]}", timeout=timeout)
        if oidc.status_code == 404:
            schema = session.get(f"http://{host}:{VECTOR_DB_PORTS['weaviate'][0]}/v1/schema", timeout=timeout)
            if schema.status_code == 200:
                findings.append(
                    _build_finding(
                        title="Weaviate Vector DB Anonymous Access Enabled",
                        severity="critical",
                        class_name="data_exfiltration",
                        owasp_category="LLM08",
                        affected_target=f"{host}:{VECTOR_DB_PORTS['weaviate'][0]}",
                        evidence="Weaviate schema endpoint was reachable while OIDC discovery was absent.",
                    )
                )
    except Exception:
        pass

    try:
        response = session.get(f"http://{host}:{VECTOR_DB_PORTS['qdrant'][0]}{VECTOR_DB_PORTS['qdrant'][1]}", timeout=timeout)
        if response.status_code == 200:
            findings.append(
                _build_finding(
                    title="Qdrant Vector DB Unauthenticated",
                    severity="critical",
                    class_name="data_exfiltration",
                    owasp_category="LLM08",
                    affected_target=f"{host}:{VECTOR_DB_PORTS['qdrant'][0]}",
                    evidence="Qdrant collections endpoint was reachable without an API key.",
                )
            )
    except Exception:
        pass

    try:
        connection = socket.create_connection((host, 19530), timeout=timeout)
        connection.close()
        health = session.get(f"http://{host}:{VECTOR_DB_PORTS['milvus'][0]}{VECTOR_DB_PORTS['milvus'][1]}", timeout=timeout)
        if health.status_code == 200:
            findings.append(
                _build_finding(
                    title="Milvus Vector DB Unencrypted",
                    severity="high",
                    class_name="data_exfiltration",
                    owasp_category="LLM08",
                    affected_target=f"{host}:19530",
                    evidence="Milvus gRPC and management health endpoints were reachable without TLS enforcement.",
                )
            )
    except Exception:
        pass

    return findings


def scan_target(target: str) -> list[Finding]:
    host = validate_target(target)
    scan_output = nmap_service_scan(host)
    ports = parse_nmap_open_ports(scan_output)
    findings: list[Finding] = []

    authless_ports: set[int] = set()
    for port, _service in ports:
        script_output = nmap_script(host, "http-auth", port)
        if script_output and "authentication" not in script_output.lower():
            authless_ports.add(port)

    urls: list[str] = []
    for port, _service in ports:
        scheme = "https" if port in {443, 8443} else "http"
        base = f"{scheme}://{host}:{port}"
        urls.extend(f"{base}{path}" for path in AI_PATHS)

    if urls:
        responses = asyncio.run(async_probe(urls, headers={}, timeout=10))
        for response in responses:
            url = response.get("url")
            if not isinstance(url, str):
                continue
            port = urlparse(url).port
            findings.extend(analyze_discovery_response(url, response, unauthenticated=port in authless_ports))

    with requests.Session() as session:
        findings.extend(check_vector_db_auth(host, session, timeout=10))

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover and fingerprint AI infrastructure surfaces.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output")
    parser.add_argument("--push-github", action="store_true")
    parser.add_argument("--github-token")
    args = parser.parse_args()

    findings = scan_target(args.target)
    payload = [finding.to_dict() for finding in findings]
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.push_github and args.github_token:
        push_findings(findings, args.github_token)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
