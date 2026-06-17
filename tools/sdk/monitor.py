"""Monitoring decorator for agent tool calls."""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Callable, Mapping, Sequence
from functools import wraps
from typing import Any

from lib.schema import build_finding, compute_toxicity

from .client import ZenuxClient, PolicyViolationError
from .redaction import normalize_text, redact_text, truncate_text
from .session import AgentSession

RISK_PATTERNS = {
    'shell': ('tool_misuse', 'high', [
        'bash',
        'sh -c',
        'cmd.exe',
        'powershell',
        'subprocess',
        'os.system',
        'exec(',
        'curl ',
        'wget ',
    ]),
    'credential': ('credential_theft', 'critical', [
        'secret',
        'token',
        'password',
        'private key',
        'api key',
        'credential',
        'env',
    ]),
    'network': ('data_exfiltration', 'high', [
        'http://',
        'https://',
        'fetch(',
        'requests.get',
        'urllib',
        'socket',
    ]),
}


def _render_call(tool_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    return truncate_text(
        redact_text(
            normalize_text(
                {
                    'tool': tool_name,
                    'args': args,
                    'kwargs': kwargs,
                },
                800,
            ),
        ),
        800,
    )


def _looks_risky(rendered_call: str, tool_name: str) -> list[tuple[str, str, str]]:
    lowered = f'{tool_name.lower()} {rendered_call.lower()}'
    matches: list[tuple[str, str, str]] = []

    for _, (class_name, severity, needles) in RISK_PATTERNS.items():
        if any(needle in lowered for needle in needles):
            matches.append((class_name, severity, needles[0]))

    return matches


def _build_finding(tool_name: str, class_name: str, severity: str, rendered_call: str, needle: str):
    title_map = {
        'tool_misuse': 'Potential shell or execution capability exposed in agent tool call',
        'credential_theft': 'Credential-like material observed in agent tool call',
        'data_exfiltration': 'External network access observed in agent tool call',
    }

    remediation = {
        'tool_misuse': [
            'Review why the agent requested shell-style execution.',
            'Reduce the tool surface to the minimum needed for the task.',
            'Require explicit approval for write-capable or system-level actions.',
        ],
        'credential_theft': [
            'Remove secrets from the agent context and tool inputs.',
            'Use scoped secrets or short-lived credentials.',
            'Rotate anything that might have been exposed.',
        ],
        'data_exfiltration': [
            'Review outbound network access and destination allowlists.',
            'Block unexpected HTTP or socket access from the agent.',
            'Keep sensitive data out of tool arguments and responses.',
        ],
    }

    toxicity = compute_toxicity(
        20 if class_name == 'tool_misuse' else 30 if class_name == 'credential_theft' else 25,
        20 if class_name == 'tool_misuse' else 30 if class_name == 'credential_theft' else 25,
        15 if class_name == 'tool_misuse' else 10 if class_name == 'credential_theft' else 20,
        20 if class_name == 'tool_misuse' else 35 if class_name == 'credential_theft' else 25,
    )

    return build_finding(
        tool_id='BG',
        title=title_map[class_name],
        severity=severity,  # type: ignore[arg-type]
        class_name=class_name,  # type: ignore[arg-type]
        owasp_category='LLM06',
        mitre_atlas_technique='AML.T0049 - Autonomous Impact',
        source='background-agent-sdk',
        toxicity=toxicity,
        fixability='short_term',
        remediation_steps=remediation[class_name],
        affected_target=tool_name,
        evidence=rendered_call[:800] + (f' [match={needle}]' if needle else ''),
    )


def _classify_tool_call(tool_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]):
    rendered_call = _render_call(tool_name, args, kwargs)
    findings = []
    for class_name, severity, needle in _looks_risky(rendered_call, tool_name):
        findings.append(_build_finding(tool_name, class_name, severity, rendered_call, needle))
    return rendered_call, findings


def monitor(
    subject: ZenuxClient | AgentSession,
    *,
    tool_name: str | None = None,
    source: str | None = None,
    policy_hook: str | None = None,
    enforce_policy: bool = False,
    report_findings: bool = True,
):
    """Decorate a sync or async tool function with Zenux telemetry.

    The wrapper logs start/stop metadata into the agent session, redacts the
    call arguments, and emits heuristic findings when the call appears risky.
    Policy evaluation is available but opt-in so telemetry never becomes the
    reason a tool stops working.
    """

    session = subject if isinstance(subject, AgentSession) else None
    client = subject.client if isinstance(subject, AgentSession) else subject
    monitor_tool_name = tool_name or 'tool'
    monitor_source = source or client.source

    def decorator(fn: Callable[..., Any]):
        if inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any):
                rendered_call, findings = _classify_tool_call(monitor_tool_name, args, kwargs)
                active_session = session or client.session(source=monitor_source)
                started_here = session is None

                if started_here:
                    active_session.__enter__()

                active_session.log_tool_call(monitor_tool_name, {'args': args, 'kwargs': kwargs}, metadata={'source': monitor_source})

                if policy_hook:
                    policy_result = client.evaluate_policy(
                        hook=policy_hook,
                        event={
                            'tool': monitor_tool_name,
                            'call': rendered_call,
                            'source': monitor_source,
                        },
                        actor_id=active_session.agent_id,
                        requested_by=active_session.agent_id,
                        asset_id=active_session.repo,
                    )
                    active_session.log_event(
                        action='agent.policy.evaluated',
                        summary=f'Policy evaluated for {monitor_tool_name}.',
                        metadata={
                            'decision': (policy_result or {}).get('overallDecision', 'unknown'),
                        },
                    )
                    if enforce_policy and policy_result and policy_result.get('overallDecision') == 'block':
                        active_session.log_event(
                            action='agent.tool_call.blocked',
                            summary=f'Tool call blocked by policy: {monitor_tool_name}.',
                            metadata={
                                'decision': policy_result.get('overallDecision'),
                            },
                        )
                        if started_here:
                            active_session.__exit__(None, None, None)
                        raise PolicyViolationError(
                            f'Policy blocked monitored tool call: {monitor_tool_name}',
                            policy_result=policy_result,
                        )

                if findings and report_findings:
                    active_session.report_findings(findings)

                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    active_session.log_event(
                        action='agent.tool_call.failed',
                        summary=f'Tool call failed: {monitor_tool_name}.',
                        metadata={
                            'error': truncate_text(redact_text(str(exc)), 240),
                            'errorType': type(exc).__name__,
                        },
                    )
                    if started_here:
                        active_session.__exit__(type(exc), exc, exc.__traceback__)
                    raise

                if isinstance(result, Sequence) and not isinstance(result, (str, bytes, bytearray)):
                    result_list = list(result)
                    if result_list and all(hasattr(item, 'to_dict') or isinstance(item, Mapping) for item in result_list):
                        if report_findings:
                            active_session.report_findings(result_list)
                        active_session.log_response(
                            monitor_tool_name,
                            result_list,
                            metadata={'findingCount': len(result_list)},
                        )
                    else:
                        active_session.log_response(monitor_tool_name, result_list)
                else:
                    active_session.log_response(monitor_tool_name, result)

                if started_here:
                    active_session.__exit__(None, None, None)
                return result

            return async_wrapper

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            rendered_call, findings = _classify_tool_call(monitor_tool_name, args, kwargs)
            active_session = session or client.session(source=monitor_source)
            started_here = session is None

            if started_here:
                active_session.__enter__()

            active_session.log_tool_call(monitor_tool_name, {'args': args, 'kwargs': kwargs}, metadata={'source': monitor_source})

            if policy_hook:
                policy_result = client.evaluate_policy(
                    hook=policy_hook,
                    event={
                        'tool': monitor_tool_name,
                        'call': rendered_call,
                        'source': monitor_source,
                    },
                    actor_id=active_session.agent_id,
                    requested_by=active_session.agent_id,
                    asset_id=active_session.repo,
                )
                active_session.log_event(
                    action='agent.policy.evaluated',
                    summary=f'Policy evaluated for {monitor_tool_name}.',
                    metadata={
                        'decision': (policy_result or {}).get('overallDecision', 'unknown'),
                    },
                )
                if enforce_policy and policy_result and policy_result.get('overallDecision') == 'block':
                    active_session.log_event(
                        action='agent.tool_call.blocked',
                        summary=f'Tool call blocked by policy: {monitor_tool_name}.',
                        metadata={
                            'decision': policy_result.get('overallDecision'),
                        },
                    )
                    if started_here:
                        active_session.__exit__(None, None, None)
                    raise PolicyViolationError(
                        f'Policy blocked monitored tool call: {monitor_tool_name}',
                        policy_result=policy_result,
                    )

            if findings and report_findings:
                active_session.report_findings(findings)

            try:
                result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                active_session.log_event(
                    action='agent.tool_call.failed',
                    summary=f'Tool call failed: {monitor_tool_name}.',
                    metadata={
                        'error': truncate_text(redact_text(str(exc)), 240),
                        'errorType': type(exc).__name__,
                    },
                )
                if started_here:
                    active_session.__exit__(type(exc), exc, exc.__traceback__)
                raise

            if isinstance(result, Sequence) and not isinstance(result, (str, bytes, bytearray)):
                result_list = list(result)
                if result_list and all(hasattr(item, 'to_dict') or isinstance(item, Mapping) for item in result_list):
                    if report_findings:
                        active_session.report_findings(result_list)
                    active_session.log_response(
                        monitor_tool_name,
                        result_list,
                        metadata={'findingCount': len(result_list)},
                    )
                else:
                    active_session.log_response(monitor_tool_name, result_list)
            else:
                active_session.log_response(monitor_tool_name, result)

            if started_here:
                active_session.__exit__(None, None, None)
            return result

        return wrapper

    return decorator
