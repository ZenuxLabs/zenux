"""Zenux Scan Toolkit subprocess wrappers.

Tool name: Kali tool adapters
OWASP coverage: LLM03, LLM06, LLM07, LLM10
MITRE mapping: AML.T0007, AML.T0010, AML.T0017, AML.T0029
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any


def _run(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        return None


def parse_nmap_open_ports(output: str) -> list[tuple[int, str]]:
    """Extract open tcp ports and service banners from nmap output."""

    ports: list[tuple[int, str]] = []
    for match in re.finditer(r"(?m)^(\d+)/tcp\s+open(?:\|\w+)?\s+(.+)$", output):
        ports.append((int(match.group(1)), match.group(2).strip()))
    return ports


def nmap_service_scan(host: str, ports: str = "80,443,8000,8001,8080,8888,3000,5000,11434,7860") -> str:
    result = _run(["nmap", "-Pn", "-sV", "-p", ports, host])
    if result is None:
        return ""
    return f"{result.stdout}\n{result.stderr}".strip()


def nmap_script(host: str, script: str, port: int) -> str:
    result = _run(["nmap", "-Pn", "--script", script, "-p", str(port), host])
    if result is None:
        return ""
    return f"{result.stdout}\n{result.stderr}".strip()


def gobuster_dir(url: str, wordlist_path: str, threads: int = 10) -> list[str]:
    result = _run(
        ["gobuster", "dir", "-q", "-u", url, "-w", wordlist_path, "-t", str(threads)],
    )
    if result is None:
        return []

    matches: list[str] = []
    for line in result.stdout.splitlines():
        match = re.search(r"(?P<path>/\S+)", line.strip())
        if match:
            matches.append(match.group("path"))
    return matches


def nikto_scan(url: str) -> str:
    result = _run(["nikto", "-host", url])
    if result is None:
        return ""
    return f"{result.stdout}\n{result.stderr}".strip()


def httpx_probe(url: str) -> dict[str, Any]:
    result = _run(["httpx", "-u", url, "--json", "-status-code", "-title", "-web-server", "-silent"])
    if result is None or not result.stdout.strip():
        return {"status": None, "title": "", "headers": {}, "body_snippet": ""}

    line = result.stdout.strip().splitlines()[-1]
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return {"status": None, "title": "", "headers": {}, "body_snippet": line[:240]}

    headers: dict[str, str] = {}
    webserver = payload.get("webserver")
    if isinstance(webserver, str) and webserver:
        headers["server"] = webserver

    body_snippet = ""
    for key in ("body", "body_preview", "response-body"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            body_snippet = value[:240]
            break

    return {
        "status": payload.get("status-code") or payload.get("status_code"),
        "title": payload.get("title", ""),
        "headers": headers,
        "body_snippet": body_snippet,
    }

