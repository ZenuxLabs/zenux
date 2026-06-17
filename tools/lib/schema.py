"""Zenux Scan Toolkit finding schema.

Tool name: canonical finding schema
OWASP coverage: LLM01-LLM10
MITRE mapping: multiple AML techniques depending on caller
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import count
from time import time
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]
LLMThreatClass = Literal[
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
]
Fixability = Literal["immediate", "short_term", "structural", "research_required"]
ToxicityLabel = Literal["low", "medium", "high", "critical"]

_finding_counter = count(1)


@dataclass(slots=True)
class ToxicityBreakdown:
    """Structured toxicity score used by all scan findings."""

    overall: int
    accessLevel: int
    dataExposure: int
    lateralMovement: int
    exploitMaturity: int
    label: ToxicityLabel

    def to_dict(self) -> dict[str, int | str]:
        return {
            "overall": self.overall,
            "accessLevel": self.accessLevel,
            "dataExposure": self.dataExposure,
            "lateralMovement": self.lateralMovement,
            "exploitMaturity": self.exploitMaturity,
            "label": self.label,
        }


def compute_toxicity(access: int, data: int, lateral: int, exploit: int) -> ToxicityBreakdown:
    """Compute the weighted 0-100 toxicity score for a finding."""

    weighted = int(access * 0.25 + data * 0.30 + lateral * 0.25 + exploit * 0.20)
    overall = max(0, min(100, weighted * 4))

    if overall <= 30:
        label: ToxicityLabel = "low"
    elif overall <= 60:
        label = "medium"
    elif overall <= 80:
        label = "high"
    else:
        label = "critical"

    return ToxicityBreakdown(
        overall=overall,
        accessLevel=access,
        dataExposure=data,
        lateralMovement=lateral,
        exploitMaturity=exploit,
        label=label,
    )


def _generate_finding_id(tool_id: str) -> str:
    return f"SCAN-{tool_id}-{int(time() * 1000)}-{next(_finding_counter)}"


@dataclass(slots=True)
class Finding:
    """Canonical scan finding shape shared across all native tools."""

    title: str
    severity: Severity
    className: LLMThreatClass
    owaspCategory: str
    mitreAtlasTechnique: str
    source: str
    toxicity: ToxicityBreakdown
    fixability: Fixability
    remediationSteps: list[str]
    affectedTarget: str
    evidence: str
    id: str
    status: str = "new"
    detectedAt: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    riskScore: int = field(init=False)

    def __post_init__(self) -> None:
        self.evidence = self.evidence[:800]
        self.riskScore = self.toxicity.overall

    def _derive_priority(self) -> str:
        return {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4"}.get(self.severity, "p3")

    def to_dict(self) -> dict[str, object]:
        return {
            # Ingest API required fields
            "title": self.title,
            "summary": self.evidence[:300],
            "source": self.source,
            "threatClass": self.className,
            "severity": self.severity,
            "priority": self._derive_priority(),
            # Ingest API optional fields
            "status": self.status,
            "riskScore": self.riskScore,
            "remediationSummary": " ".join(self.remediationSteps),
            # Tool metadata (not in ingest API but useful for local reporting)
            "id": self.id,
            "owaspCategory": self.owaspCategory,
            "mitreAtlasTechnique": self.mitreAtlasTechnique,
            "toxicity": self.toxicity.to_dict(),
            "fixability": self.fixability,
            "affectedTarget": self.affectedTarget,
            "evidence": self.evidence,
            "detectedAt": self.detectedAt,
        }


@dataclass(slots=True)
class MCPRugPullFinding(Finding):
    """Extended finding shape for MCP tool-definition mutation tracking."""

    mutation_type: str = ""
    original_definition: dict[str, object] = field(default_factory=dict)
    mutated_definition: dict[str, object] = field(default_factory=dict)
    etdi_signed: bool = False

    def to_dict(self) -> dict[str, object]:
        payload = super().to_dict()
        payload.update(
            {
                "mutation_type": self.mutation_type,
                "original_definition": self.original_definition,
                "mutated_definition": self.mutated_definition,
                "etdi_signed": self.etdi_signed,
            }
        )
        return payload


def build_finding(
    *,
    tool_id: str,
    title: str,
    severity: Severity,
    class_name: LLMThreatClass,
    owasp_category: str,
    mitre_atlas_technique: str,
    source: str,
    toxicity: ToxicityBreakdown,
    fixability: Fixability,
    remediation_steps: list[str],
    affected_target: str,
    evidence: str,
) -> Finding:
    """Create a finding with a canonical id and normalized score fields."""

    return Finding(
        id=_generate_finding_id(tool_id),
        title=title,
        severity=severity,
        className=class_name,
        owaspCategory=owasp_category,
        mitreAtlasTechnique=mitre_atlas_technique,
        source=source,
        toxicity=toxicity,
        fixability=fixability,
        remediationSteps=remediation_steps,
        affectedTarget=affected_target,
        evidence=evidence,
    )
