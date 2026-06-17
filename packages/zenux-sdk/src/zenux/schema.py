"""Zenux finding and trace schema."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]
ThreatClass = Literal[
    "prompt_injection",
    "indirect_injection",
    "jailbreak",
    "data_exfiltration",
    "tool_misuse",
    "mcp_abuse",
    "credential_theft",
    "model_poisoning",
    "intent_escalation",
    "supply_chain",
    "other",
]


@dataclass
class Finding:
    """A security finding to report to Zenux.

    Required:
        title: Short description of the finding.

    Optional but recommended:
        severity:   "low" | "medium" | "high" | "critical" (default "medium")
        threat_class: One of the ThreatClass literals.
        asset_id:   Identifier of the affected asset/agent/service.
        description: Detailed explanation.
        remediation: Suggested remediation steps.
        tags:       Arbitrary string labels.
        source:     Originating scanner or system (default "sdk").
        external_key: Idempotency key — re-submitting the same key deduplicates.
    """

    title: str
    severity: Severity = "medium"
    threat_class: ThreatClass = "other"
    asset_id: str | None = None
    description: str = ""
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    source: str = "sdk"
    external_key: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "title": self.title,
            "severity": self.severity,
            "className": self.threat_class,
            "source": self.source,
            "summary": self.description,
            "remediationSummary": self.remediation or None,
            "tags": self.tags,
        }
        if self.asset_id is not None:
            d["assetId"] = self.asset_id
        if self.external_key is not None:
            d["externalKey"] = self.external_key
        return d
