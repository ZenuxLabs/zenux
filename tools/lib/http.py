"""Zenux Scan Toolkit async HTTP helpers.

Tool name: async HTTP helpers
OWASP coverage: LLM01, LLM04, LLM06, LLM08, LLM10
MITRE mapping: AML.T0017, AML.T0020, AML.T0029, AML.T0049, AML.T0051
Safety disclaimer: For authorized testing only. Only run against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp


def parse_header_string(header_value: str | None) -> dict[str, str]:
    if not header_value:
        return {}

    name, separator, value = header_value.partition(":")
    if not separator:
        return {}
    return {name.strip(): value.strip()}


async def async_probe(urls: list[str], headers: dict[str, str], timeout: int) -> list[dict[str, Any]]:
    """Perform parallel GET probes and return normalized response metadata."""

    client_timeout = aiohttp.ClientTimeout(total=timeout)

    async def _fetch(session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
        try:
            async with session.get(url, headers=headers) as response:
                text = await response.text()
                return {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body_snippet": text[:400],
                }
        except Exception as exc:  # pragma: no cover - exercised through callers
            return {
                "url": url,
                "status": None,
                "headers": {},
                "body_snippet": "",
                "error": str(exc),
            }

    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        return await asyncio.gather(*(_fetch(session, url) for url in urls))


async def post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: int,
) -> dict[str, Any] | None:
    """POST JSON and return a normalized response payload."""

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.post(url, json=payload, headers=headers) as response:
                try:
                    body: Any = await response.json(content_type=None)
                except Exception:
                    body = await response.text()

                if isinstance(body, dict):
                    body["status"] = response.status
                    body["headers"] = dict(response.headers)
                    return body

                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": str(body),
                }
    except Exception:
        return None
