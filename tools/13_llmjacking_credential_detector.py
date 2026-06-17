"""Zenux Scan Toolkit: LLMjacking & AI credential abuse detector.

Tool name: 13_llmjacking_credential_detector
OWASP coverage: LLM10
MITRE mapping: AML.T0040 - ML Model Access
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.

Based on Operation Bizarre Bazaar (Dec 2025 - Jan 2026): 35,000 attack sessions
targeting exposed AI infrastructure.  Attackers steal credentials, query
Bedrock/Vertex/Azure OpenAI at $100K+/day, and resell access.

Detects:
  - Exposed /v1/chat/completions with no auth accepting unbounded max_tokens
  - API key patterns in .env / docker-compose.yml / config files
  - Missing rate limiting (rapid requests all succeed)
  - Missing token limits (max_tokens=999999 accepted)
  - Credential echo in error messages
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from pathlib import Path
from typing import Any

import aiohttp
import requests

from lib.http import parse_header_string
from lib.reporter import push_findings
from lib.schema import Finding, build_finding, compute_toxicity
from lib.target import validate_target

TOOL_ID = "13"
SOURCE = "13_llmjacking_credential_detector"
MITRE_TECHNIQUE = "AML.T0040 - ML Model Access"

# API key regex patterns with provider identification
CREDENTIAL_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, provider_label, severity)
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI", "critical"),
    (r"sk-ant-[A-Za-z0-9\-]{20,}", "Anthropic", "critical"),
    (r"sk-proj-[A-Za-z0-9\-]{20,}", "OpenAI Project", "critical"),
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key", "critical"),
    (r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", "AWS Secret Key (candidate)", "high"),
    (r"AIza[A-Za-z0-9\-_]{35}", "Google AI API Key", "critical"),
    (r"gsk_[A-Za-z0-9]{20,}", "Groq", "critical"),
    (r"xai-[A-Za-z0-9]{20,}", "xAI/Grok", "critical"),
    (r"hf_[A-Za-z0-9]{20,}", "HuggingFace", "high"),
    (r"r8_[A-Za-z0-9]{20,}", "Replicate", "high"),
]

# Files commonly containing leaked credentials
SENSITIVE_FILE_PATTERNS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.override.yml",
    ".docker/config.json",
    "config.json",
    "config.yaml",
    "config.yml",
    "secrets.json",
    "credentials.json",
    ".aws/credentials",
    "application.properties",
    "appsettings.json",
]


def _build_finding(
    title: str,
    severity: str,
    target: str,
    evidence: str,
    fixability: str = "immediate",
) -> Finding:
    severity_scores = {
        "critical": (25, 25, 25, 25),
        "high": (20, 20, 20, 15),
        "medium": (15, 10, 10, 10),
        "low": (5, 5, 5, 5),
    }
    scores = severity_scores.get(severity, (10, 10, 10, 10))
    return build_finding(
        tool_id=TOOL_ID,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        class_name="credential_theft",
        owasp_category="LLM10",
        mitre_atlas_technique=MITRE_TECHNIQUE,
        source=SOURCE,
        toxicity=compute_toxicity(*scores),
        fixability=fixability,  # type: ignore[arg-type]
        remediation_steps=[
            "Rotate all exposed API keys immediately.",
            "Add authentication to all AI inference endpoints.",
            "Enforce per-request max_tokens and rate limits at the API edge.",
            "Remove credentials from source-controlled config files; use a secrets manager.",
            "Enable billing alerts and usage anomaly detection on cloud AI accounts.",
        ],
        affected_target=target,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Endpoint probes
# ---------------------------------------------------------------------------

def probe_unauthenticated_endpoint(
    base_url: str,
    timeout: int = 10,
) -> list[dict[str, Any]]:
    """Check if /v1/chat/completions is reachable without authentication."""
    issues: list[dict[str, Any]] = []
    url = f"{base_url.rstrip('/')}/v1/chat/completions"

    try:
        response = requests.post(
            url,
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "Say hello"}],
            },
            timeout=timeout,
        )
        if response.status_code == 200:
            issues.append({
                "type": "unauthenticated_endpoint",
                "severity": "critical",
                "detail": f"Endpoint {url} accepts requests without authentication.",
                "evidence": {"status": 200, "body_snippet": response.text[:300]},
            })
    except requests.RequestException:
        pass

    return issues


def probe_unbounded_max_tokens(
    base_url: str,
    headers: dict[str, str],
    timeout: int = 10,
) -> list[dict[str, Any]]:
    """Test whether endpoint accepts max_tokens=999999 without rejection."""
    issues: list[dict[str, Any]] = []
    url = f"{base_url.rstrip('/')}/v1/chat/completions"

    try:
        response = requests.post(
            url,
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "Say hello"}],
                "max_tokens": 999999,
            },
            headers=headers,
            timeout=timeout,
        )
        if response.status_code == 200:
            issues.append({
                "type": "unbounded_max_tokens",
                "severity": "high",
                "detail": f"Endpoint accepted max_tokens=999999 without rejection.",
                "evidence": {"status": 200, "body_snippet": response.text[:300]},
            })
    except requests.RequestException:
        pass

    return issues


def probe_credential_echo(
    base_url: str,
    headers: dict[str, str],
    timeout: int = 10,
) -> list[dict[str, Any]]:
    """Check if error messages echo back credentials or API keys."""
    issues: list[dict[str, Any]] = []
    url = f"{base_url.rstrip('/')}/v1/chat/completions"

    try:
        response = requests.post(
            url,
            json={"model": "nonexistent-model-xyz", "messages": []},
            headers=headers,
            timeout=timeout,
        )
        body = response.text
        for pattern, provider, _sev in CREDENTIAL_PATTERNS:
            if re.search(pattern, body):
                issues.append({
                    "type": "credential_echo",
                    "severity": "critical",
                    "detail": f"Error response from {url} echoes {provider} credential pattern.",
                    "evidence": {"status": response.status_code, "body_snippet": body[:300]},
                })
                break  # one finding per endpoint is enough
    except requests.RequestException:
        pass

    return issues


async def _rate_limit_burst(
    url: str,
    headers: dict[str, str],
    count: int = 10,
) -> list[dict[str, Any]]:
    """Send N rapid concurrent requests and check if all succeed."""
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=15),
    ) as session:
        async def _send() -> dict[str, Any]:
            try:
                async with session.post(
                    url,
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [{"role": "user", "content": "ping"}],
                    },
                    headers=headers,
                ) as resp:
                    return {"status": resp.status}
            except Exception as exc:
                return {"status": None, "error": str(exc)}

        results = await asyncio.gather(*(_send() for _ in range(count)))
        return list(results)


def probe_rate_limiting(
    base_url: str,
    headers: dict[str, str],
    burst_count: int = 10,
) -> list[dict[str, Any]]:
    """Test for missing rate limiting with rapid burst requests."""
    issues: list[dict[str, Any]] = []
    url = f"{base_url.rstrip('/')}/v1/chat/completions"

    try:
        results = asyncio.run(_rate_limit_burst(url, headers, burst_count))
    except Exception:
        return issues

    successes = sum(1 for r in results if r.get("status") == 200)
    if successes == burst_count:
        issues.append({
            "type": "missing_rate_limit",
            "severity": "high",
            "detail": f"All {burst_count} rapid requests succeeded — no rate limiting detected.",
            "evidence": {"total": burst_count, "successes": successes},
        })

    return issues


# ---------------------------------------------------------------------------
# Credential file scanning
# ---------------------------------------------------------------------------

def scan_credential_files(directory: str) -> list[dict[str, Any]]:
    """Scan local files for exposed API key patterns."""
    issues: list[dict[str, Any]] = []
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return issues

    for pattern in SENSITIVE_FILE_PATTERNS:
        candidates = list(dir_path.rglob(pattern))
        for file_path in candidates:
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for regex, provider, severity in CREDENTIAL_PATTERNS:
                matches = re.findall(regex, content)
                if matches:
                    # Redact credentials in evidence
                    redacted = [m[:6] + "..." + m[-4:] if len(m) > 12 else "***" for m in matches]
                    rel = str(file_path.relative_to(dir_path))
                    issues.append({
                        "type": "exposed_credential",
                        "severity": severity,
                        "detail": f"Found {provider} credential pattern in {rel} "
                                  f"({len(matches)} occurrence(s)).",
                        "evidence": {"file": rel, "provider": provider, "redacted_samples": redacted[:3]},
                    })

    return issues


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def scan_endpoint(
    endpoint: str,
    auth_header: str | None = None,
) -> list[Finding]:
    """Scan a live AI endpoint for LLMjacking indicators."""
    validate_target(endpoint)
    base_url = endpoint if endpoint.startswith(("http://", "https://")) else f"https://{endpoint}"
    headers = parse_header_string(auth_header)
    all_issues: list[dict[str, Any]] = []

    all_issues.extend(probe_unauthenticated_endpoint(base_url))
    all_issues.extend(probe_unbounded_max_tokens(base_url, headers))
    all_issues.extend(probe_credential_echo(base_url, headers))
    all_issues.extend(probe_rate_limiting(base_url, headers))

    return [
        _build_finding(
            title=issue["detail"][:120],
            severity=issue["severity"],
            target=endpoint,
            evidence=json.dumps(issue),
        )
        for issue in all_issues
    ]


def scan_files(directory: str) -> list[Finding]:
    """Scan local files for leaked AI credentials."""
    all_issues = scan_credential_files(directory)
    return [
        _build_finding(
            title=issue["detail"][:120],
            severity=issue["severity"],
            target=directory,
            evidence=json.dumps(issue),
        )
        for issue in all_issues
    ]


def scan_target(
    target: str,
    auth_header: str | None = None,
) -> list[Finding]:
    """Combined scan: if target looks like a URL, probe endpoints;
    if it looks like a path, scan files; otherwise try both."""
    findings: list[Finding] = []

    if target.startswith(("http://", "https://")):
        findings.extend(scan_endpoint(target, auth_header))
    elif Path(target).is_dir():
        findings.extend(scan_files(target))
    else:
        # Treat as hostname — probe endpoint
        findings.extend(scan_endpoint(target, auth_header))

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect LLMjacking exposure: unauthenticated endpoints, "
                    "leaked credentials, missing rate limits."
    )
    parser.add_argument(
        "--target", required=True,
        help="AI endpoint URL or local directory to scan for credentials",
    )
    parser.add_argument("--auth-header")
    parser.add_argument("--scan-files", dest="scan_dir",
                        help="Also scan this directory for leaked credentials")
    parser.add_argument("--output")
    parser.add_argument("--push-github", action="store_true")
    parser.add_argument("--github-token")
    args = parser.parse_args()

    findings = scan_target(args.target, auth_header=args.auth_header)
    if args.scan_dir:
        findings.extend(scan_files(args.scan_dir))

    payload = [finding.to_dict() for finding in findings]
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.push_github and args.github_token:
        push_findings(findings, args.github_token)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
