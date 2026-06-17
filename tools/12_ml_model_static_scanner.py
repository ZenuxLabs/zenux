"""Zenux Scan Toolkit: ML model static file scanner.

Tool name: 12_ml_model_static_scanner
OWASP coverage: LLM03
MITRE mapping: AML.T0010 - Model Supply Chain Compromise
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.

Detects pickle-based RCE risk, non-standard compression bypasses (7z / bzip2),
unsafe PyTorch PTH pickle streams, trust_remote_code in configs, and incomplete
model cards.  Supports local directory paths and huggingface://owner/repo URIs.
Downloaded models are never cached (tempfile with delete=True).
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import requests

from lib.reporter import push_findings
from lib.schema import Finding, build_finding, compute_toxicity

TOOL_ID = "12"
SOURCE = "12_ml_model_static_scanner"
MITRE_TECHNIQUE = "AML.T0010 - Model Supply Chain Compromise"

# Magic bytes for non-standard compression bypass detection
MAGIC_7Z = b"\x37\x7a\xbc\xaf"       # 7z archive header
MAGIC_BZIP2 = b"\x42\x5a\x68"        # bzip2 header  "BZh"
MAGIC_PICKLE_V4 = b"\x80\x04"        # pickle protocol 4
MAGIC_PICKLE_V3 = b"\x80\x03"        # pickle protocol 3
MAGIC_ZIP = b"PK\x03\x04"            # ZIP / PyTorch checkpoint

# Pickle opcodes that indicate RCE risk when combined with callables
PICKLE_REDUCE_OPCODE = b"\x52"        # REDUCE opcode 'R'
PICKLE_GLOBAL_OPCODE = b"\x63"        # GLOBAL opcode 'c'
PICKLE_STACK_GLOBAL = b"\x8c"         # SHORT_BINUNICODE (used in protocol 4+ for module refs)

DANGEROUS_CALLABLE_PATTERNS: list[bytes] = [
    b"os\nsystem",
    b"os\npopen",
    b"subprocess\ncall",
    b"subprocess\nPopen",
    b"subprocess\ncheck_output",
    b"builtins\neval",
    b"builtins\nexec",
    b"builtins\ngetattr",
    b"nt\nsystem",
    b"posix\nsystem",
    b"webbrowser\nopen",
    b"shutil\nrmtree",
]

HF_API_BASE = "https://huggingface.co/api/models"
HF_FILE_BASE = "https://huggingface.co"

MODEL_EXTENSIONS = {
    ".pkl", ".pickle", ".pt", ".pth", ".bin",
    ".onnx", ".safetensors", ".pb", ".h5",
    ".tflite", ".ckpt", ".joblib",
}

CONFIG_FILENAMES = {
    "config.json", "tokenizer_config.json",
    "generation_config.json", "adapter_config.json",
    "preprocessor_config.json",
}


def _build_finding(
    title: str,
    severity: str,
    target: str,
    evidence: str,
    fixability: str = "immediate",
) -> Finding:
    severity_scores = {
        "critical": (25, 25, 20, 25),
        "high": (20, 20, 15, 15),
        "medium": (15, 10, 10, 10),
        "low": (5, 5, 5, 5),
    }
    scores = severity_scores.get(severity, (10, 10, 10, 10))
    return build_finding(
        tool_id=TOOL_ID,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        class_name="supply_chain",
        owasp_category="LLM03",
        mitre_atlas_technique=MITRE_TECHNIQUE,
        source=SOURCE,
        toxicity=compute_toxicity(*scores),
        fixability=fixability,  # type: ignore[arg-type]
        remediation_steps=[
            "Replace pickle-based model artifacts with safetensors format.",
            "Scan all model files for malicious opcodes before deployment.",
            "Remove trust_remote_code=True from model configs.",
            "Validate compression formats match expected archive types.",
            "Ensure model cards are complete with safety information.",
        ],
        affected_target=target,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Pickle analysis
# ---------------------------------------------------------------------------

def scan_pickle_bytes(data: bytes, file_path: str) -> list[dict[str, Any]]:
    """Scan raw bytes for pickle RCE indicators.

    Returns a list of issue dicts with keys: type, severity, detail.
    """
    issues: list[dict[str, Any]] = []

    is_pickle = data[:2] in (MAGIC_PICKLE_V4, MAGIC_PICKLE_V3)
    is_zip_with_pkl = data[:4] == MAGIC_ZIP and b"data.pkl" in data[:8192]
    if not is_pickle and not is_zip_with_pkl:
        return issues

    # Check for REDUCE + callable (RCE risk)
    has_reduce = PICKLE_REDUCE_OPCODE in data
    has_global = PICKLE_GLOBAL_OPCODE in data or b"GLOBAL" in data

    for pattern in DANGEROUS_CALLABLE_PATTERNS:
        if pattern in data:
            issues.append({
                "type": "pickle_rce_callable",
                "severity": "critical",
                "detail": f"Pickle stream in {file_path} contains dangerous callable "
                          f"'{pattern.decode('ascii', errors='replace')}'"
                          + (" with REDUCE opcode" if has_reduce else ""),
            })

    if has_reduce and has_global and not issues:
        issues.append({
            "type": "pickle_reduce_global",
            "severity": "high",
            "detail": f"Pickle stream in {file_path} uses REDUCE+GLOBAL opcodes "
                      f"(potential arbitrary code execution).",
        })

    if not issues and (is_pickle or is_zip_with_pkl):
        sev = "high" if is_pickle else "medium"
        issues.append({
            "type": "pickle_unsafe_format",
            "severity": sev,
            "detail": f"File {file_path} uses pickle-based serialization "
                      f"(inherently unsafe for untrusted models).",
        })

    return issues


# ---------------------------------------------------------------------------
# Compression bypass detection
# ---------------------------------------------------------------------------

def scan_compression_bypass(data: bytes, file_path: str) -> list[dict[str, Any]]:
    """Detect non-standard compression used to bypass pickle scanners (7z/bzip2)."""
    issues: list[dict[str, Any]] = []

    if data[:4] == MAGIC_7Z:
        issues.append({
            "type": "compression_bypass_7z",
            "severity": "critical",
            "detail": f"File {file_path} uses 7z compression (magic 37 7A BC AF). "
                      f"This technique was used in Feb 2025 HuggingFace attacks to "
                      f"bypass PickleScan.",
        })
    if data[:3] == MAGIC_BZIP2:
        issues.append({
            "type": "compression_bypass_bzip2",
            "severity": "critical",
            "detail": f"File {file_path} uses bzip2 compression (magic 42 5A 68). "
                      f"Non-standard compression can bypass pickle scanners.",
        })

    return issues


# ---------------------------------------------------------------------------
# Config analysis
# ---------------------------------------------------------------------------

def scan_config_file(data: bytes, file_path: str) -> list[dict[str, Any]]:
    """Check model config files for dangerous settings."""
    issues: list[dict[str, Any]] = []
    try:
        config = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return issues

    if config.get("trust_remote_code") is True:
        issues.append({
            "type": "trust_remote_code",
            "severity": "high",
            "detail": f"Config {file_path} has trust_remote_code=True, enabling "
                      f"arbitrary remote code execution on model load.",
        })

    custom_code_keys = ["auto_map", "custom_pipelines"]
    for key in custom_code_keys:
        if key in config:
            issues.append({
                "type": "custom_code_mapping",
                "severity": "medium",
                "detail": f"Config {file_path} contains '{key}' mapping that may "
                          f"load untrusted code.",
            })

    return issues


# ---------------------------------------------------------------------------
# Model card completeness
# ---------------------------------------------------------------------------

def scan_model_card(content: str | None, target: str) -> list[dict[str, Any]]:
    """Check for incomplete or missing model cards."""
    issues: list[dict[str, Any]] = []

    if not content or len(content.strip()) < 50:
        issues.append({
            "type": "missing_model_card",
            "severity": "medium",
            "detail": f"Model at {target} has no or incomplete model card "
                      f"(README.md < 50 chars). Missing safety/bias documentation.",
        })
        return issues

    required_sections = ["license", "intended use", "limitation", "bias"]
    lower = content.lower()
    missing = [s for s in required_sections if s not in lower]
    if missing:
        issues.append({
            "type": "incomplete_model_card",
            "severity": "low",
            "detail": f"Model card at {target} is missing sections: "
                      f"{', '.join(missing)}.",
        })

    return issues


# ---------------------------------------------------------------------------
# HuggingFace repo support
# ---------------------------------------------------------------------------

def _hf_list_files(owner: str, repo: str) -> list[dict[str, str]]:
    """List files in a HuggingFace model repository."""
    url = f"{HF_API_BASE}/{owner}/{repo}"
    response = requests.get(url, timeout=15)
    response.raise_for_status()
    payload = response.json()
    siblings = payload.get("siblings", [])
    return [{"rfilename": s["rfilename"]} for s in siblings if "rfilename" in s]


def _hf_download_file(owner: str, repo: str, filename: str) -> bytes:
    """Download a file from HuggingFace to a temp location and return bytes.

    Never caches — uses tempfile with delete=True.
    """
    url = f"{HF_FILE_BASE}/{owner}/{repo}/resolve/main/{filename}"
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        response = requests.get(url, timeout=30, stream=True, headers={"Range": "bytes=0-16383"})
        response.raise_for_status()
        data = response.content
        tmp.write(data)
        tmp.flush()
        return data


def _hf_get_readme(owner: str, repo: str) -> str | None:
    """Fetch the README / model card from HuggingFace."""
    url = f"{HF_FILE_BASE}/{owner}/{repo}/resolve/main/README.md"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return None


def scan_huggingface_repo(owner: str, repo: str) -> list[Finding]:
    """Scan a HuggingFace model repository for security issues."""
    target = f"huggingface://{owner}/{repo}"
    all_issues: list[dict[str, Any]] = []

    try:
        files = _hf_list_files(owner, repo)
    except Exception as exc:
        return [_build_finding(
            title=f"Failed to list HuggingFace repo {target}",
            severity="low",
            target=target,
            evidence=str(exc),
        )]

    for file_info in files:
        filename = file_info["rfilename"]
        ext = Path(filename).suffix.lower()
        basename = Path(filename).name.lower()

        should_scan = (
            ext in MODEL_EXTENSIONS
            or basename in CONFIG_FILENAMES
            or ext in (".7z", ".bz2")
        )
        if not should_scan:
            continue

        try:
            data = _hf_download_file(owner, repo, filename)
        except Exception:
            continue

        if basename in CONFIG_FILENAMES:
            all_issues.extend(scan_config_file(data, f"{target}/{filename}"))
        else:
            all_issues.extend(scan_pickle_bytes(data, f"{target}/{filename}"))
            all_issues.extend(scan_compression_bypass(data, f"{target}/{filename}"))

    # Model card check
    readme = _hf_get_readme(owner, repo)
    all_issues.extend(scan_model_card(readme, target))

    return [
        _build_finding(
            title=issue["detail"][:120],
            severity=issue["severity"],
            target=target,
            evidence=json.dumps(issue),
        )
        for issue in all_issues
    ]


# ---------------------------------------------------------------------------
# Local directory scanning
# ---------------------------------------------------------------------------

def scan_local_directory(directory: str) -> list[Finding]:
    """Scan a local directory of model files for security issues."""
    target = directory
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return [_build_finding(
            title=f"Target directory does not exist: {directory}",
            severity="low",
            target=target,
            evidence=json.dumps({"path": directory, "exists": False}),
        )]

    all_issues: list[dict[str, Any]] = []

    for file_path in sorted(dir_path.rglob("*")):
        if not file_path.is_file():
            continue

        ext = file_path.suffix.lower()
        basename = file_path.name.lower()

        should_scan = (
            ext in MODEL_EXTENSIONS
            or basename in CONFIG_FILENAMES
            or ext in (".7z", ".bz2")
        )
        if not should_scan:
            continue

        try:
            data = file_path.read_bytes()[:16384]
        except OSError:
            continue

        rel = str(file_path.relative_to(dir_path))
        if basename in CONFIG_FILENAMES:
            all_issues.extend(scan_config_file(data, rel))
        else:
            all_issues.extend(scan_pickle_bytes(data, rel))
            all_issues.extend(scan_compression_bypass(data, rel))

    # Model card
    readme_path = dir_path / "README.md"
    readme_content = None
    if readme_path.is_file():
        try:
            readme_content = readme_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    all_issues.extend(scan_model_card(readme_content, target))

    return [
        _build_finding(
            title=issue["detail"][:120],
            severity=issue["severity"],
            target=target,
            evidence=json.dumps(issue),
        )
        for issue in all_issues
    ]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_target(target: str) -> list[Finding]:
    """Scan a model target (local path or huggingface://owner/repo URI)."""
    if target.startswith("huggingface://"):
        parts = target.removeprefix("huggingface://").strip("/").split("/", 1)
        if len(parts) != 2:
            return [_build_finding(
                title="Invalid HuggingFace URI format",
                severity="low",
                target=target,
                evidence=json.dumps({"uri": target, "expected": "huggingface://owner/repo"}),
            )]
        return scan_huggingface_repo(parts[0], parts[1])

    return scan_local_directory(target)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Statically scan ML model files for pickle RCE, compression "
                    "bypass, and unsafe configs."
    )
    parser.add_argument(
        "--target", required=True,
        help="Local directory path or huggingface://owner/repo URI",
    )
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
