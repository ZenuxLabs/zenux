"""Zenux Scan Toolkit: model supply chain scanner.

Tool name: 06_model_supply_chain_scanner
OWASP coverage: LLM03, LLM04
MITRE mapping: AML.T0010 - Model Supply Chain Compromise
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable
from urllib.parse import urljoin

import requests

from lib.kali import gobuster_dir
from lib.reporter import push_findings
from lib.schema import Finding, build_finding, compute_toxicity
from lib.target import validate_target

TOOL_ID = "06"
SOURCE = "06_model_supply_chain_scanner"
MITRE_TECHNIQUE = "AML.T0010 - Model Supply Chain Compromise"
WORDLIST_ENTRIES = [
    "models/",
    "model/",
    "weights/",
    "checkpoints/",
    "artifacts/",
    "saved_model/",
    "model.pkl",
    "model.pickle",
    "model.pt",
    "model.pth",
    "pytorch_model.bin",
    "model.onnx",
    "model.safetensors",
    "config.json",
    "tokenizer.json",
    "vocab.json",
    "merges.txt",
    "generation_config.json",
    "adapter_config.json",
    "adapter_model.safetensors",
    "training_args.bin",
]


def write_wordlist(entries: Iterable[str]) -> str:
    with NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", prefix="gal-model-wordlist-", delete=False) as handle:
        handle.write("\n".join(entries))
        handle.write("\n")
        return handle.name


def _build_finding(title: str, severity: str, class_name: str, target: str, evidence: str) -> Finding:
    return build_finding(
        tool_id=TOOL_ID,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        class_name=class_name,  # type: ignore[arg-type]
        owasp_category="LLM03" if class_name == "supply_chain" else "LLM04",
        mitre_atlas_technique=MITRE_TECHNIQUE,
        source=SOURCE,
        toxicity=compute_toxicity(20 if severity != "critical" else 25, 20, 15, 25 if severity == "critical" else 15),
        fixability="immediate" if severity == "critical" else "short_term",
        remediation_steps=[
            "Stop serving model artifacts directly over HTTP without authentication.",
            "Restrict access to model files behind an authenticated API or object store.",
            "Run Tool 12 (ml_model_static_scanner) against exposed artifacts for content analysis.",
        ],
        affected_target=target,
        evidence=evidence,
    )


def analyze_artifact_exposure(path: str, head_bytes: bytes, target: str) -> Finding | None:
    """Detect that a sensitive model artifact is reachable over HTTP.

    This tool owns HTTP-level exposure detection only — it reports that a file
    type is accessible, not what its contents contain. Byte-level content
    analysis (pickle opcodes, trust_remote_code, compression bypass) is the
    exclusive responsibility of Tool 12 (ml_model_static_scanner).
    """
    lowered_path = path.lower()
    if head_bytes.startswith(b"<!doctype html") or head_bytes.startswith(b"<html"):
        return None
    if lowered_path.endswith(".safetensors") or head_bytes.startswith(b'{"\x00\x00'):
        return None
    if lowered_path.endswith("config.json"):
        return _build_finding(
            title=f"Model config file publicly reachable at {path}",
            severity="medium",
            class_name="supply_chain",
            target=target,
            evidence=f"HTTP-accessible config at {path} — run Tool 12 to analyse contents.",
        )
    if head_bytes.startswith(b"\x80\x04") or head_bytes.startswith(b"\x80\x03"):
        return _build_finding(
            title=f"Pickle model artifact exposed over HTTP at {path}",
            severity="high",
            class_name="supply_chain",
            target=target,
            evidence=f"Pickle magic bytes detected at {path} — run Tool 12 for opcode analysis.",
        )
    if head_bytes.startswith(b"PK\x03\x04"):
        return _build_finding(
            title=f"ZIP or PyTorch checkpoint exposed over HTTP at {path}",
            severity="high",
            class_name="supply_chain",
            target=target,
            evidence=f"ZIP magic bytes detected at {path} — run Tool 12 for content analysis.",
        )
    if lowered_path.endswith(".onnx"):
        return _build_finding(
            title=f"ONNX artifact exposed at {path}",
            severity="low",
            class_name="supply_chain",
            target=target,
            evidence=f"ONNX file accessible over HTTP at {path}.",
        )
    return None


def scan_target(target: str) -> list[Finding]:
    normalized_host = validate_target(target)
    base_url = target if target.startswith(("http://", "https://")) else f"https://{normalized_host}"
    wordlist_path = write_wordlist(WORDLIST_ENTRIES)
    findings: list[Finding] = []
    for path in gobuster_dir(base_url, wordlist_path):
        response = requests.get(
            urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
            headers={"Range": "bytes=0-4095"},
            timeout=10,
        )
        finding = analyze_artifact_exposure(path, response.content[:4096], base_url)
        if finding:
            findings.append(finding)
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Enumerate model artifacts and assess supply-chain risk.")
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

