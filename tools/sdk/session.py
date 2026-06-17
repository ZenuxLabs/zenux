"""Agent session context manager for Zenux runtime reporting."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from lib.schema import Finding

from .redaction import normalize_metadata, normalize_text, redact_text, truncate_text

if TYPE_CHECKING:
    from .client import ZenuxClient


def _summarize_response(response: Any) -> str:
    if isinstance(response, Sequence) and not isinstance(response, (str, bytes, bytearray)):
        items = list(response)
        if items and all(
            isinstance(item, Finding)
            or isinstance(item, Mapping)
            or (hasattr(item, 'to_dict') and callable(getattr(item, 'to_dict')))
            for item in items
        ):
            titles: list[str] = []
            for item in items[:3]:
                if isinstance(item, Finding):
                    title = item.title
                elif isinstance(item, Mapping):
                    title = item.get('title')
                elif hasattr(item, 'to_dict') and callable(getattr(item, 'to_dict')):
                    payload = item.to_dict()
                    title = payload.get('title') if isinstance(payload, Mapping) else None
                else:
                    title = None

                if isinstance(title, str) and title.strip():
                    titles.append(truncate_text(redact_text(title.strip()), 120))

            if titles:
                return truncate_text(redact_text(f"Returned {len(items)} finding(s): {', '.join(titles)}"), 320)
            return truncate_text(f"Returned {len(items)} finding(s).", 320)

    return normalize_text(response, 320)


@dataclass(slots=True)
class AgentSession:
    """Buffered audit-event session for a single dispatched agent."""

    client: 'ZenuxClient'
    agent_id: str | None = None
    repo: str | None = None
    work_item_id: str | None = None
    source: str | None = None
    session_id: str | None = None
    _events: list[dict[str, Any]] = field(default_factory=list, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.agent_id is None:
            self.agent_id = self.client.agent_id
        if self.repo is None:
            self.repo = self.client.repo
        if self.work_item_id is None:
            self.work_item_id = self.client.work_item_id
        if self.source is None:
            self.source = self.client.source
        if self.session_id is None:
            self.session_id = str(uuid.uuid4())

    @property
    def external_key(self) -> str:
        parts = [self.agent_id or 'unknown-agent', self.repo or 'no-repo', self.work_item_id or 'no-work-item', self.session_id or 'unknown-session']
        return ':'.join(parts)

    def __enter__(self) -> 'AgentSession':
        self.log_event(
            action='agent.session.started',
            summary='Background agent session started.',
            metadata={
                'agentId': self.agent_id,
                'repo': self.repo,
                'workItemId': self.work_item_id,
                'source': self.source,
            },
        )
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is not None:
            self.log_event(
                action='agent.session.failed',
                summary='Background agent session failed.',
                metadata={
                    'error': normalize_text(exc, 240),
                    'errorType': type(exc).__name__,
                },
            )
        else:
            self.log_event(
                action='agent.session.completed',
                summary='Background agent session completed.',
                metadata={
                    'eventCount': len(self._events),
                },
            )

        if self._events:
            self.client.report_audit_events(self._events)
            self.client.flush()

        self._closed = True
        return False

    def _base_metadata(self) -> dict[str, str | int | float | bool | None]:
        return {
            'agentId': self.agent_id,
            'repo': self.repo,
            'workItemId': self.work_item_id,
            'sessionId': self.session_id,
            'source': self.source,
        }

    def log_event(
        self,
        *,
        action: str,
        summary: str,
        target_type: str = 'agent_session',
        target_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        payload = {
            'actorId': self.agent_id or 'unknown-agent',
            'actorType': 'service',
            'action': action,
            'targetType': target_type,
            'targetId': target_id or self.session_id or 'unknown-session',
            'summary': truncate_text(redact_text(summary), 400),
            'metadata': {
                **self._base_metadata(),
                **normalize_metadata(metadata),
            },
        }
        self._events.append(payload)

    def log_prompt(self, prompt: str, *, metadata: Mapping[str, Any] | None = None) -> None:
        self.log_event(
            action='agent.prompt.received',
            summary='Agent prompt received.',
            metadata={
                'promptSnippet': truncate_text(redact_text(prompt), 320),
                'promptLength': len(prompt),
                **(dict(metadata) if metadata else {}),
            },
        )

    def log_tool_call(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any] | Sequence[Any] | None = None,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.log_event(
            action='agent.tool_call.started',
            summary=f'Tool call started: {tool_name}.',
            metadata={
                'toolName': tool_name,
                'toolArguments': normalize_text(tool_args or {}, 320),
                **(dict(metadata) if metadata else {}),
            },
        )

    def log_response(
        self,
        tool_name: str,
        response: Any,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.log_event(
            action='agent.tool_call.completed',
            summary=f'Tool response captured: {tool_name}.',
            metadata={
                'toolName': tool_name,
                'responseSnippet': _summarize_response(response),
                **(dict(metadata) if metadata else {}),
            },
        )

    def report_finding(self, finding: Finding | Mapping[str, Any], *, target_id: str | None = None) -> None:
        self.client.report_finding(finding, session_id=self.session_id, target_id=target_id)

        if isinstance(finding, Finding):
            title = finding.title
            class_name = finding.className
            severity = finding.severity
        elif isinstance(finding, Mapping):
            title = str(finding.get('title') or 'Agent finding')
            class_name = str(finding.get('className') or finding.get('class_name') or 'prompt_injection')
            severity = str(finding.get('severity') or 'medium')
        else:
            title = 'Agent finding'
            class_name = 'prompt_injection'
            severity = 'medium'

        self.log_event(
            action='agent.finding.reported',
            summary=f'Finding reported: {title}.',
            metadata={
                'findingTitle': title,
                'findingClass': class_name,
                'findingSeverity': severity,
            },
        )

    def report_findings(self, findings: Sequence[Finding | Mapping[str, Any]], *, target_id: str | None = None) -> None:
        if not findings:
            return

        self.client.report_findings(findings, session_id=self.session_id, target_id=target_id)
        self.log_event(
            action='agent.findings.reported',
            summary=f'{len(findings)} finding(s) reported.',
            metadata={
                'findingCount': len(findings),
            },
        )

    def monitor(self, *args: Any, **kwargs: Any):
        from .monitor import monitor

        return monitor(self, *args, **kwargs)
