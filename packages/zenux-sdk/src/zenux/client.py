"""Zenux ingest client."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

import requests

from .schema import Finding


class ZenuxError(RuntimeError):
    """Raised when the Zenux API returns an error."""


class ZenuxClient:
    """Client for reporting findings and traces to Zenux.

    Configuration via environment variables (or constructor args):
        ZENUX_ENDPOINT      Base URL of your Zenux deployment (e.g. https://security.example.com)
        ZENUX_INGEST_SECRET Ingest bearer token
        ZENUX_ORG_ID        Organisation identifier (defaults to first path in endpoint)

    Example::

        from zenux import ZenuxClient, Finding

        client = ZenuxClient()
        client.ingest(Finding(
            title="Prompt injection in summarise_email tool",
            severity="high",
            threat_class="prompt_injection",
            asset_id="email-agent-prod",
        ))
    """

    def __init__(
        self,
        endpoint: str | None = None,
        secret: str | None = None,
        *,
        org_id: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.endpoint = (
            endpoint
            or os.environ.get("ZENUX_ENDPOINT", "")
            or os.environ.get("ZENUX_ENDPOINT", "")
        ).rstrip("/")
        self.secret = (
            secret
            or os.environ.get("ZENUX_INGEST_SECRET", "")
            or os.environ.get("INGEST_SECRET", "")
            or os.environ.get("ZENUX_INGEST_SECRET", "")
        )
        self.org_id = org_id or os.environ.get("ZENUX_ORG_ID", "")
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.endpoint and self.secret)

    def ingest(self, *findings: Finding, sync_to_github: bool = False) -> dict[str, Any]:
        """Report one or more findings to Zenux.

        Returns the parsed API response dict, or an empty dict if the client is
        not configured (endpoint or secret missing) — so calls are always safe
        to fire-and-forget without wrapping in try/except.

        Raises ZenuxError if the API returns a non-2xx status.
        """
        if not findings:
            return {}
        if not self.is_configured:
            return {}

        payload: dict[str, Any] = {
            "findings": [f.to_dict() for f in findings],
            "syncToGitHub": sync_to_github,
        }
        if self.org_id:
            payload["orgId"] = self.org_id

        headers = {
            "Authorization": f"Bearer {self.secret}",
            "Content-Type": "application/json",
        }

        resp = requests.post(
            f"{self.endpoint}/api/ingest/findings",
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )

        if not resp.ok:
            raise ZenuxError(f"Zenux API error {resp.status_code}: {resp.text[:200]}")

        return resp.json() if resp.content else {}

    def ingest_batch(self, findings: Sequence[Finding], **kwargs: Any) -> dict[str, Any]:
        """Alias for ``ingest(*findings)`` when you already have a list."""
        return self.ingest(*findings, **kwargs)
