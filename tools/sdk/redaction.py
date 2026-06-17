"""Shared redaction helpers for the Zenux SDK."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ('OpenAI API key', re.compile(r'sk-[A-Za-z0-9]{20,}')),
    ('Anthropic API key', re.compile(r'sk-ant-[A-Za-z0-9-]{20,}')),
    ('OpenAI project key', re.compile(r'sk-proj-[A-Za-z0-9-]{20,}')),
    ('GitHub personal access token', re.compile(r'ghp_[A-Za-z0-9]{36}')),
    ('GitHub fine-grained token', re.compile(r'github_pat_[A-Za-z0-9_]{22,}')),
    ('AWS access key', re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}')),
    ('Google AI key', re.compile(r'AIza[A-Za-z0-9_-]{35}')),
    ('Groq key', re.compile(r'gsk_[A-Za-z0-9]{20,}')),
    ('xAI key', re.compile(r'xai-[A-Za-z0-9]{20,}')),
    ('HuggingFace token', re.compile(r'hf_[A-Za-z0-9]{20,}')),
    ('Replicate token', re.compile(r'r8_[A-Za-z0-9]{20,}')),
]

_PROMPT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'ignore previous instructions', re.IGNORECASE),
    re.compile(r'ignore all prior', re.IGNORECASE),
    re.compile(r'disregard your instructions', re.IGNORECASE),
    re.compile(r'new persona', re.IGNORECASE),
    re.compile(r'you are now', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
]

_SENSITIVE_ENV_PATTERN = re.compile(
    r'\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY|WEBHOOK|SIGNATURE|KEY)[A-Z0-9_]*)\s*=\s*(?:\'[^\']*\'|"[^"]*"|[^\s"`\'"]+)'
)


def truncate_text(text: str, max_length: int = 320) -> str:
    if len(text) <= max_length:
        return text

    return f'{text[: max_length - 3]}...'


def redact_text(text: str) -> str:
    redacted = text

    for label, pattern in _CREDENTIAL_PATTERNS:
        redacted = pattern.sub(f'[REDACTED:{label}]', redacted)

    for pattern in _PROMPT_PATTERNS:
        redacted = pattern.sub('[REDACTED:PROMPT_INJECTION]', redacted)

    redacted = _SENSITIVE_ENV_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED:{match.group(1)}]", redacted)
    return redacted


def normalize_text(value: Any, max_length: int = 320) -> str:
    if value is None:
        return ''

    if isinstance(value, str):
        return truncate_text(redact_text(value), max_length)

    if isinstance(value, (bytes, bytearray)):
        return truncate_text(redact_text(value.decode('utf-8', errors='replace')), max_length)

    if isinstance(value, Mapping) or (
        isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    ):
        try:
            rendered = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
        except Exception:
            rendered = str(value)
        return truncate_text(redact_text(rendered), max_length)

    return truncate_text(redact_text(str(value)), max_length)


def normalize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, str | int | float | bool | None]:
    if not metadata:
        return {}

    result: dict[str, str | int | float | bool | None] = {}
    for key, value in metadata.items():
        if value is None or isinstance(value, (bool, int, float)):
            result[key] = value
            continue

        result[key] = normalize_text(value, 240)

    return result
