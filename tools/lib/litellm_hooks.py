"""Zenux Scan Toolkit LiteLLM guardrail hook templates.

Tool name: LiteLLM guardrail hook templates
OWASP coverage: LLM01, LLM05
MITRE mapping: educational remediation template only
Safety disclaimer: For authorized testing only. Copy these templates only into systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import Awaitable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib import request as urllib_request


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _mapping_value(source: Any, key: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(key, default)
    return getattr(source, key, default)


def _coerce_int(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, bool):
        return default

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return int(round(value))

    if isinstance(value, str):
        try:
            return int(round(float(value.strip())))
        except ValueError:
            return default

    return default


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value

    if isinstance(value, str):
        candidate = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            return None

    return None


def _duration_ms(start: Any, end: Any) -> int:
    start_dt = _parse_datetime(start)
    end_dt = _parse_datetime(end)
    if start_dt is not None and end_dt is not None:
        delta = end_dt - start_dt
        return max(0, int(round(delta.total_seconds() * 1000)))

    if isinstance(start, (int, float)) and isinstance(end, (int, float)):
        delta = end - start
        if abs(start) >= 10_000_000_000 or abs(end) >= 10_000_000_000:
            return max(0, int(round(delta)))
        return max(0, int(round(delta * 1000)))

    return 0


def _extract_latency_ms(data: Any, response: Any | None = None) -> int:
    for candidate in (
        _mapping_value(data, "latency_ms"),
        _mapping_value(data, "latencyMs"),
        _mapping_value(data, "duration_ms"),
        _mapping_value(data, "durationMs"),
        _mapping_value(response, "latency_ms"),
        _mapping_value(response, "latencyMs"),
    ):
        if candidate is not None:
            return _coerce_int(candidate)

    start = _mapping_value(data, "start_time", _mapping_value(data, "startTime"))
    end = _mapping_value(data, "end_time", _mapping_value(data, "endTime"))
    if start is not None and end is not None:
        return _duration_ms(start, end)

    return 0


def _extract_token_count(source: Any, *keys: str) -> int:
    for key in keys:
        value = _mapping_value(source, key)
        if value is not None:
            return _coerce_int(value)
    return 0


def _extract_user_id(user_api_key_dict: Any, data: Any) -> str:
    user_id = (
        _mapping_value(user_api_key_dict, "user_id")
        or _mapping_value(user_api_key_dict, "userId")
        or _mapping_value(data, "user_id")
        or _mapping_value(data, "userId")
        or "unknown"
    )
    return str(user_id)


_CREDENTIAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-ant-[A-Za-z0-9-]{20,}", re.IGNORECASE), "Anthropic API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9-]{20,}", re.IGNORECASE), "OpenAI project key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}", re.IGNORECASE), "OpenAI API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}", re.IGNORECASE), "GitHub personal access token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}", re.IGNORECASE), "GitHub fine-grained token"),
    (re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}"), "AWS access key"),
    (re.compile(r"AIza[A-Za-z0-9_-]{35}"), "Google AI key"),
    (re.compile(r"gsk_[A-Za-z0-9]{20,}", re.IGNORECASE), "Groq key"),
    (re.compile(r"xai-[A-Za-z0-9]{20,}", re.IGNORECASE), "xAI key"),
    (re.compile(r"hf_[A-Za-z0-9]{20,}", re.IGNORECASE), "HuggingFace token"),
    (re.compile(r"r8_[A-Za-z0-9]{20,}", re.IGNORECASE), "Replicate token"),
]

_GENERIC_SECRET_PATTERN = re.compile(r"(?i)(password|secret|token)\s*[:=]\s*\S+")


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, Mapping):
        for key in ("content", "text", "output", "value", "message", "prompt"):
            nested = value.get(key)
            if nested is not None:
                text = _coerce_text(nested)
                if text:
                    return text

        try:
            return json.dumps(value, ensure_ascii=False)
        except TypeError:
            return str(value)

    if isinstance(value, list):
        return " ".join(part for part in (_coerce_text(item) for item in value) if part)

    return str(value)


def _extract_message_text(data: Any) -> str:
    segments: list[str] = []

    messages = _mapping_value(data, "messages", [])
    if not isinstance(messages, list):
        messages = []

    segments.extend(text for text in (_coerce_text(message) for message in messages) if text)

    for key in ("prompt", "input", "user_prompt", "userPrompt", "content"):
        text = _coerce_text(_mapping_value(data, key))
        if text:
            segments.append(text)

    return " ".join(segments)


def _detect_credential_label(text: str) -> str | None:
    for pattern, label in _CREDENTIAL_PATTERNS:
        if pattern.search(text):
            return label

    if _GENERIC_SECRET_PATTERN.search(text):
        return "credential pattern"

    return None


def _fire_and_forget(coro: Awaitable[Any]) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(coro)
        return

    loop.create_task(coro)


def _post_json_sync(path: str, body: dict[str, Any]) -> None:
    endpoint = os.environ.get("ZENUX_ENDPOINT", "").rstrip("/")
    secret = os.environ.get("INGEST_SECRET", "")
    if not endpoint or not secret:
        return

    payload = json.dumps(body).encode("utf-8")
    request_obj = urllib_request.Request(
        f"{endpoint}/{path.lstrip('/')}",
        data=payload,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib_request.urlopen(request_obj, timeout=5) as response:
        response.read()


async def _post_to_zenux(finding_payload: dict[str, Any]) -> None:
    """Fire-and-forget: POST a detection signal to the Zenux ingest pipeline.

    Security note: This function must NEVER include the raw sensitive content
    (injection text, credential value, etc.) in the payload. Only classification
    metadata and sanitised signals are transmitted.
    """

    try:
        await asyncio.to_thread(_post_json_sync, "api/ingest/findings", {"findings": [finding_payload]})
    except Exception:  # noqa: BLE001
        pass  # never let reporting failure break the guardrail


async def _post_trace_to_zenux(trace_payload: dict[str, Any]) -> None:
    """Fire-and-forget: POST LLM call metadata to the Zenux trace ingest pipeline.

    Security note: This function must NEVER include prompt content or response
    content in the payload. Only call metadata is transmitted.
    """

    try:
        await asyncio.to_thread(_post_json_sync, "api/ingest/traces", {"traces": [trace_payload]})
    except Exception:  # noqa: BLE001
        pass  # never let reporting failure break the guardrail


def render_litellm_proxy_config() -> str:
    """Return a copy-paste example for wiring Zenux into a LiteLLM proxy.

    This is documentation-only text. It does not install anything by itself.
    """

    return """# Zenux LiteLLM proxy example
# Save as litellm_config.yaml and load it with the LiteLLM proxy.
# Environment variables are supplied at runtime:
#   ZENUX_ENDPOINT=https://api.example.com
#   INGEST_SECRET=<ingest bearer token>
#   ZENUX_POLICY_HOOK=<policy hook name, e.g. litellm.pre_call>  # required for policy enforcement

guardrails:
  - guardrail_name: zenux-policy-enforcement
    litellm_params:
      guardrail: custom_guardrail.PolicyEnforcementHook
      mode: pre_call
  - guardrail_name: zenux-prompt-injection
    litellm_params:
      guardrail: custom_guardrail.PromptInjectionHook
      mode: pre_call
  - guardrail_name: zenux-credential-leak
    litellm_params:
      guardrail: custom_guardrail.CredentialLeakHook
      mode: pre_call
  - guardrail_name: zenux-sensitive-data
    litellm_params:
      guardrail: custom_guardrail.SensitiveDataHook
      mode: post_call
  - guardrail_name: zenux-trace-reporting
    litellm_params:
      guardrail: custom_guardrail.TraceReportingHook
      mode: post_call
"""


class PromptInjectionHook:
    """Pre-call hook that blocks obvious prompt-injection attempts."""

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):  # noqa: ANN001
        messages = _mapping_value(data, "messages", [])
        if not isinstance(messages, list):
            messages = []

        injection_patterns = [
            "ignore previous instructions",
            "ignore all prior",
            "disregard your instructions",
            "you are now",
            "new persona",
            "jailbreak",
        ]

        for message in messages:
            content = ""
            if isinstance(message, Mapping):
                content = _coerce_text(message.get("content", ""))
            else:
                content = _coerce_text(message)

            lowered = content.lower()
            matched = next((pattern for pattern in injection_patterns if pattern in lowered), None)
            if matched:
                # Report detection signal - NOT the raw content
                _fire_and_forget(
                    _post_to_zenux(
                        {
                            "title": "Prompt Injection Attempt Blocked",
                            "className": "prompt_injection",
                            "severity": "high",
                            "source": "litellm_hook:PromptInjectionHook",
                            "description": f"Injection pattern '{matched}' detected in request messages.",
                            "remediationSteps": [
                                "Validate and sanitise all user-supplied inputs before forwarding to the LLM.",
                                "Apply input guardrails at the application layer.",
                            ],
                            "affectedTarget": "litellm-proxy",
                            "owaspCategory": "LLM01",
                            "mitreAtlasTechnique": "AML.T0051 - LLM Prompt Injection",
                            "riskScore": 70,
                            "detectedAt": _iso_now(),
                            "toxicity": {
                                "overall": 70,
                                "accessLevel": 8,
                                "dataExposure": 6,
                                "lateralMovement": 5,
                                "exploitMaturity": 7,
                                "label": "high",
                            },
                        }
                    )
                )
                raise ValueError("Request blocked: prompt injection pattern detected")

        return data


class CredentialLeakHook:
    """Pre-call hook that blocks obvious secret or credential leakage."""

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):  # noqa: ANN001
        request_text = _extract_message_text(data)
        credential_label = _detect_credential_label(request_text)
        if credential_label:
            risk = 90 if credential_label != "credential pattern" else 75
            _fire_and_forget(
                _post_to_zenux(
                    {
                        "title": f"Credential Leak Blocked in LLM Request: {credential_label}",
                        "className": "credential_theft",
                        "severity": "critical" if risk >= 85 else "high",
                        "source": "litellm_hook:CredentialLeakHook",
                        "description": (
                            f"Pattern matching '{credential_label}' was detected in request messages. "
                            "Raw credential value was NOT transmitted to Zenux."
                        ),
                        "remediationSteps": [
                            "Remove secrets from user prompts and system prompts before forwarding to the LLM.",
                            "Store credentials in a secrets manager or vault.",
                            "Treat the request as unsafe until the exposed secret is rotated.",
                        ],
                        "affectedTarget": "litellm-proxy",
                        "owaspCategory": "LLM02",
                        "mitreAtlasTechnique": "AML.T0040 - ML Model Access",
                        "riskScore": risk,
                        "detectedAt": _iso_now(),
                        "toxicity": {
                            "overall": risk,
                            "accessLevel": 9,
                            "dataExposure": 9,
                            "lateralMovement": 5,
                            "exploitMaturity": 8,
                            "label": "critical" if risk >= 85 else "high",
                        },
                    }
                )
            )
            raise ValueError("Request blocked: credential pattern detected")

        return data


class SensitiveDataHook:
    """Post-call hook that blocks likely secret or credential leakage."""

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):  # noqa: ANN001
        response_text = _coerce_text(response)
        credential_label = _detect_credential_label(response_text)

        if credential_label:
            risk = 90 if credential_label != "credential pattern" else 75
            # Report detection signal - NOT the raw credential value
            _fire_and_forget(
                _post_to_zenux(
                    {
                        "title": f"Credential Leakage in LLM Response: {credential_label}",
                        "className": "data_exfiltration",
                        "severity": "critical" if risk >= 85 else "high",
                        "source": "litellm_hook:SensitiveDataHook",
                        "description": (
                            f"Pattern matching '{credential_label}' detected in LLM response output. "
                            "Raw credential value was NOT transmitted to Zenux."
                        ),
                        "remediationSteps": [
                            "Review the system prompt and context provided to the model.",
                            "Ensure no secrets are injected into prompts.",
                            "Apply output sanitisation before returning responses to clients.",
                        ],
                        "affectedTarget": "litellm-proxy",
                        "owaspCategory": "LLM02",
                        "mitreAtlasTechnique": "AML.T0040 - ML Model Access",
                        "riskScore": risk,
                        "detectedAt": _iso_now(),
                        "toxicity": {
                            "overall": risk,
                            "accessLevel": 9,
                            "dataExposure": 10,
                            "lateralMovement": 4,
                            "exploitMaturity": 8,
                            "label": "critical" if risk >= 85 else "high",
                        },
                    }
                )
            )
            raise ValueError(f"Response blocked: {credential_label} detected in output")

        return response


class TraceReportingHook:
    """Post-call hook that ships LLM call metadata to the Zenux trace ingest pipeline.

    Only metadata is transmitted - never prompt content or response content.
    """

    def _build_trace(
        self,
        data: Any,
        user_api_key_dict: Any,  # noqa: ANN401
        policy_decision: str,
        input_tokens: int,
        output_tokens: int,
        blocked_by: str | None = None,
        response: Any | None = None,
    ) -> dict[str, Any]:
        model = _mapping_value(data, "model", _mapping_value(data, "model_name", "unknown"))
        trace: dict[str, Any] = {
            "model": str(model),
            "userId": _extract_user_id(user_api_key_dict, data),
            "inputTokens": max(0, _coerce_int(input_tokens)),
            "outputTokens": max(0, _coerce_int(output_tokens)),
            "latencyMs": _extract_latency_ms(data, response),
            "policyDecision": policy_decision,
            "blockedBy": blocked_by,
            "timestamp": _iso_now(),
            "source": "litellm-proxy",
        }

        request_id = _mapping_value(data, "request_id", _mapping_value(data, "requestId"))
        if request_id is not None:
            trace["requestId"] = str(request_id)

        call_type = _mapping_value(data, "call_type", _mapping_value(data, "callType"))
        if call_type is not None:
            trace["callType"] = str(call_type)

        provider = _mapping_value(data, "provider", _mapping_value(data, "litellm_provider"))
        if provider is not None:
            trace["provider"] = str(provider)

        return trace

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):  # noqa: ANN001
        """Report metadata for every successful LLM call."""
        usage = _mapping_value(response, "usage") or _mapping_value(data, "usage") or {}

        input_tokens = _extract_token_count(usage, "prompt_tokens", "input_tokens")
        if input_tokens == 0:
            input_tokens = _extract_token_count(data, "prompt_tokens", "input_tokens")

        output_tokens = _extract_token_count(usage, "completion_tokens", "output_tokens")
        if output_tokens == 0:
            output_tokens = _extract_token_count(data, "completion_tokens", "output_tokens")

        trace = self._build_trace(
            data=data,
            user_api_key_dict=user_api_key_dict,
            policy_decision="allow",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            response=response,
        )
        _fire_and_forget(_post_trace_to_zenux(trace))
        return response

    async def async_post_call_failure_hook(self, data, user_api_key_dict, exception):  # noqa: ANN001
        """Report metadata for every blocked or failed LLM call."""
        blocked_by = type(exception).__name__ if exception is not None else None

        input_tokens = _extract_token_count(data, "prompt_tokens", "input_tokens")
        output_tokens = _extract_token_count(data, "completion_tokens", "output_tokens")

        trace = self._build_trace(
            data=data,
            user_api_key_dict=user_api_key_dict,
            policy_decision="block",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            blocked_by=blocked_by,
        )
        _fire_and_forget(_post_trace_to_zenux(trace))


class PolicyEnforcementHook:
    """Pre-call hook that evaluates active Zenux policies before each LLM call.

    Requires ZENUX_POLICY_HOOK to be set (the policy hook name to evaluate).
    When the overall decision is 'block', raises litellm.AuthenticationError
    to abort the call and prevent it reaching the provider.

    Addresses #208: LiteLLM proxy boundary — policy enforcement.
    """

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):  # noqa: ANN001
        policy_hook = os.environ.get("ZENUX_POLICY_HOOK", "").strip()
        if not policy_hook:
            return data  # no policy configured — pass through

        endpoint = os.environ.get("ZENUX_ENDPOINT", "").rstrip("/")
        secret = os.environ.get("INGEST_SECRET", "")
        if not endpoint or not secret:
            return data  # can't reach Zenux — fail open

        model = _mapping_value(data, "model", _mapping_value(data, "model_name", "unknown"))
        user_id = _extract_user_id(user_api_key_dict, data)

        eval_payload: dict[str, Any] = {
            "hook": policy_hook,
            "event": {
                "model": str(model),
                "userId": user_id,
                "callType": str(call_type) if call_type else "unknown",
                "source": "litellm-proxy",
            },
            "actorId": user_id,
            "requestedBy": user_id,
        }

        try:
            result = await asyncio.to_thread(
                _post_json_sync_with_response,
                "api/policy-evaluations",
                eval_payload,
            )
        except Exception:  # noqa: BLE001
            return data  # evaluation failed — fail open

        if isinstance(result, dict) and result.get("overallDecision") == "block":
            _fire_and_forget(
                _post_to_zenux(
                    {
                        "title": f"LLM Request Blocked by Policy: {policy_hook}",
                        "className": "behavioral_drift",
                        "severity": "high",
                        "source": "litellm_hook:PolicyEnforcementHook",
                        "description": f"Policy '{policy_hook}' blocked LLM call for user {user_id} on model {model}.",
                        "remediationSteps": [
                            "Review the active policy in the Zenux dashboard.",
                            "Request a policy exception if this call was legitimate.",
                        ],
                        "affectedTarget": "litellm-proxy",
                        "owaspCategory": "LLM08",
                        "mitreAtlasTechnique": "AML.T0051 - LLM Prompt Injection",
                        "riskScore": 65,
                        "detectedAt": _iso_now(),
                    }
                )
            )
            raise ValueError(f"Request blocked by Zenux policy: {policy_hook}")

        return data


def _post_json_sync_with_response(path: str, body: dict[str, Any]) -> dict[str, Any] | None:
    """Like _post_json_sync but returns the parsed JSON response body."""
    endpoint = os.environ.get("ZENUX_ENDPOINT", "").rstrip("/")
    secret = os.environ.get("INGEST_SECRET", "")
    if not endpoint or not secret:
        return None

    payload = json.dumps(body).encode("utf-8")
    request_obj = urllib_request.Request(
        f"{endpoint}/{path.lstrip('/')}",
        data=payload,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib_request.urlopen(request_obj, timeout=5) as response:
        raw = response.read()
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None
