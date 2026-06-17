"""Zenux Scan Toolkit reporter — pushes findings to Zenux and/or GitHub.

Tool name: finding reporter
OWASP coverage: LLM01-LLM10
MITRE mapping: multiple AML techniques depending on finding
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import requests

from lib.schema import Finding

DEFAULT_REPO = "your-org/your-repo"


def _issue_body(finding: Finding) -> str:
    return "\n".join(
        [
            "## Zenux Scan Toolkit finding",
            "",
            f"**Severity**: {finding.severity}",
            f"**OWASP LLM**: {finding.owaspCategory}",
            f"**MITRE ATLAS**: {finding.mitreAtlasTechnique}",
            f"**Affected target**: {finding.affectedTarget}",
            f"**Source**: {finding.source}",
            "",
            "### Evidence",
            finding.evidence,
            "",
            "### Canonical finding",
            "```json",
            json.dumps(finding.to_dict(), indent=2),
            "```",
        ]
    )


def push_findings_to_zenux(
    findings: list[Finding],
    zenux_endpoint: str,
    ingest_secret: str,
) -> list[dict[str, Any]]:
    """Push findings to the Zenux batch ingest endpoint.

    Uses POST /api/findings/batch with the canonical to_dict() field names.
    NOTE: Only metadata and detection signals are sent. Credential values are
    never transmitted — the evidence field is already truncated to 800 chars
    by the Finding dataclass and must not contain raw secret values.
    """
    if not findings:
        return []
    try:
        response = requests.post(
            f"{zenux_endpoint.rstrip('/')}/api/findings/batch",
            headers={
                "Authorization": f"Bearer {ingest_secret}",
                "Content-Type": "application/json",
            },
            json={"findings": [f.to_dict() for f in findings]},
            timeout=15,
        )
        if not response.ok:
            print(f"[zenux] batch ingest failed {response.status_code}: {response.text[:200]}")
            return []
        data = response.json()
        created = data.get("created", 0)
        updated = data.get("updated", 0)
        errors = data.get("errors", [])
        print(f"[zenux] ingested {created} new, {updated} updated, {len(errors)} errors out of {len(findings)} findings")
        if errors:
            for err in errors:
                print(f"[zenux]   error at index {err.get('index')}: {err.get('error')}")
        return data.get("findings", [])
    except Exception as exc:
        print(f"[zenux] batch ingest error: {exc}")
        return []


# Kept for backward compatibility — delegates to push_findings_to_zenux
def push_finding_to_zenux(
    finding: Finding,
    zenux_endpoint: str,
    ingest_secret: str,
) -> dict[str, Any] | None:
    results = push_findings_to_zenux([finding], zenux_endpoint, ingest_secret)
    return results[0] if results else None


def push_finding(
    finding: Finding,
    github_token: str,
    repo: str = DEFAULT_REPO,
) -> dict[str, Any] | None:
    """Push a finding to GitHub Issues and return the created issue payload."""

    response = requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={
            "title": f"[{finding.owaspCategory}] {finding.title}",
            "labels": ["security", "incident", finding.severity],
            "body": _issue_body(finding),
        },
        timeout=20,
    )
    if not response.ok:
        return None
    return response.json()


def push_findings(
    findings: list[Finding],
    github_token: str | None = None,
    repo: str = DEFAULT_REPO,
    zenux_endpoint: str | None = None,
    ingest_secret: str | None = None,
) -> list[dict[str, Any]]:
    """Push findings to Zenux (primary) and/or GitHub Issues (secondary).

    Priority:
    1. If ZENUX_ENDPOINT + INGEST_SECRET are available, push to Zenux first.
    2. If a github_token is provided, also push to GitHub Issues.
    Falls back to GitHub-only if Zenux is not configured.
    """
    _zenux_endpoint = zenux_endpoint or os.environ.get("ZENUX_ENDPOINT", "")
    _ingest_secret = ingest_secret or os.environ.get("INGEST_SECRET", "")
    _github_token = github_token or os.environ.get("GITHUB_TOKEN", "")

    results: list[dict[str, Any]] = []

    if _zenux_endpoint and _ingest_secret:
        zenux_results = push_findings_to_zenux(findings, _zenux_endpoint, _ingest_secret)
        results.extend(zenux_results)
    elif _github_token:
        for finding in findings:
            payload = push_finding(finding, _github_token, repo=repo)
            if payload:
                results.append(payload)
            time.sleep(1)  # GitHub secondary rate limit
    else:
        print("[reporter] WARNING: No output destination configured. Set ZENUX_ENDPOINT+INGEST_SECRET or GITHUB_TOKEN.")

    return results
