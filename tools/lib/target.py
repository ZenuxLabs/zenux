"""Zenux Scan Toolkit target safety validation.

Tool name: target safety gate
OWASP coverage: LLM01-LLM10
MITRE mapping: multiple AML techniques depending on caller
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from urllib.parse import urlparse

_INTERNAL_BYPASS = "ALLOW_INTERNAL"


def _extract_host(raw_target: str) -> str:
    candidate = raw_target.strip()
    if not candidate:
        raise ValueError("target is empty")

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = parsed.hostname or parsed.path
    host = host.strip().lower()
    if not host:
        raise ValueError("target host could not be determined")
    return host


def _allow_internal() -> bool:
    return os.environ.get(_INTERNAL_BYPASS) == "1"


def validate_target(host: str) -> str:
    """Normalize and reject internal-only targets unless ALLOW_INTERNAL=1 is set."""

    normalized = _extract_host(host)

    if _allow_internal():
        print(
            f"[ALLOW_INTERNAL] Safety bypass active — internal target permitted: {normalized}",
            file=sys.stderr,
        )
        return normalized

    if normalized in {"localhost", "metadata.google.internal", "169.254.169.254"}:
        raise ValueError(f"target {normalized} is internal-only and blocked by safety policy")

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return normalized

    if address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError(f"target {normalized} is private or link-local and blocked by safety policy")

    return normalized

