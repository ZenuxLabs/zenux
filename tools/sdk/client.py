"""Non-blocking Zenux client for background-agent runtimes."""

from __future__ import annotations

import os
import queue
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, TYPE_CHECKING

import requests

from lib.schema import compute_toxicity

from .redaction import normalize_text, redact_text, truncate_text

if TYPE_CHECKING:
    from .session import AgentSession


TransportFn = Callable[[str, dict[str, Any], dict[str, str], int], Any]


class PolicyViolationError(RuntimeError):
    """Raised when policy evaluation blocks a monitored tool call."""

    def __init__(self, message: str, policy_result: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.policy_result = dict(policy_result or {})


def _default_transport(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: int) -> Any:
    response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    return response


def _extract_json(response: Any) -> Any:
    json_method = getattr(response, 'json', None)
    if callable(json_method):
        try:
            return json_method()
        except Exception:
            return None

    return None


def _safe_text(value: Any, max_length: int = 320) -> str:
    return normalize_text(value, max_length)


def _summary_from_result(result: Any) -> str:
    if isinstance(result, list):
        if not result:
            return 'No findings returned.'

        titles = []
        for item in result[:3]:
            title = getattr(item, 'title', None)
            if title is None and isinstance(item, Mapping):
                title = item.get('title')
            if isinstance(title, str) and title.strip():
                titles.append(title.strip())
        return truncate_text(redact_text(f"Returned {len(result)} findings: {', '.join(titles)}"), 320)

    return _safe_text(result, 320)


class ZenuxClient:
    """Fire-and-forget Zenux client for agent runtimes.

    The client can queue audit and finding writes on a background daemon thread
    so agent execution does not wait on telemetry. If background mode is turned
    off, requests are sent synchronously with the same sanitisation rules.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        secret: str | None = None,
        *,
        agent_id: str | None = None,
        repo: str | None = None,
        work_item_id: str | None = None,
        source: str = 'background-agent-sdk',
        session_id: str | None = None,
        background: bool = True,
        timeout_seconds: int = 5,
        transport: TransportFn | None = None,
    ) -> None:
        self.endpoint = (
            endpoint
            or os.environ.get('ZENUX_ENDPOINT', '')
            or os.environ.get('ZENUX_ENDPOINT', '')
        ).rstrip('/')
        self.secret = (
            secret
            or os.environ.get('INGEST_SECRET', '')
            or os.environ.get('ZENUX_INGEST_SECRET', '')
            or os.environ.get('CONTROL_PLANE_ADMIN_TOKEN', '')
        )
        self.agent_id = agent_id or os.environ.get('GAL_AGENT_ID') or os.environ.get('AGENT_ID') or os.environ.get('HOSTNAME') or 'unknown-agent'
        self.repo = repo or os.environ.get('GAL_REPO') or os.environ.get('GITHUB_REPOSITORY') or None
        self.work_item_id = work_item_id or os.environ.get('GAL_WORK_ITEM_ID') or os.environ.get('WORK_ITEM_ID') or None
        self.source = source
        self.session_id = session_id or os.environ.get('GAL_SESSION_ID') or str(uuid.uuid4())
        self.background = background
        self.timeout_seconds = timeout_seconds
        self._transport = transport or _default_transport
        self._queue: 'queue.Queue[tuple[str, dict[str, Any]]]' = queue.Queue()
        self._pending = 0
        self._pending_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._warned_missing_config = False

        if self.background and self.is_configured:
            self._worker = threading.Thread(target=self._worker_loop, name='zenux-sdk', daemon=True)
            self._worker.start()

    @property
    def is_configured(self) -> bool:
        return bool(self.endpoint and self.secret)

    @property
    def external_key(self) -> str:
        parts = [self.agent_id, self.repo or 'no-repo', self.work_item_id or 'no-work-item', self.session_id]
        return ':'.join(parts)

    def _warn(self, message: str) -> None:
        print(f'[zenux-sdk] {message}', file=os.sys.stderr)

    def _warn_once_missing_config(self) -> None:
        if self._warned_missing_config:
            return

        self._warned_missing_config = True
        self._warn('telemetry disabled because ZENUX_ENDPOINT or ingest secret is missing')

    def _build_headers(self) -> dict[str, str]:
        return {
            'Authorization': f'Bearer {self.secret}',
            'Content-Type': 'application/json',
        }

    def _request(self, path: str, payload: dict[str, Any]) -> Any | None:
        if not self.is_configured:
            self._warn_once_missing_config()
            return None

        url = f"{self.endpoint}/{path.lstrip('/')}"
        try:
            response = self._transport(url, payload, self._build_headers(), self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            self._warn(f'failed to send {path}: {exc}')
            return None

        if response is None:
            return None

        if not getattr(response, 'ok', True):
            status = getattr(response, 'status_code', 'unknown')
            text = truncate_text(str(getattr(response, 'text', '')), 200)
            self._warn(f'{path} returned HTTP {status}{f": {text}" if text else ""}')
            return None

        return _extract_json(response)

    def _enqueue(self, path: str, payload: dict[str, Any]) -> None:
        if not self.is_configured:
            self._warn_once_missing_config()
            return

        if not self.background:
            self._request(path, payload)
            return

        with self._pending_lock:
            self._pending += 1
        self._queue.put((path, payload))

    def _mark_done(self) -> None:
        with self._pending_lock:
            self._pending = max(0, self._pending - 1)

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                path, payload = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                self._request(path, payload)
            finally:
                self._mark_done()
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        if not self.background:
            return True

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._pending_lock:
                if self._pending <= 0:
                    return True
            time.sleep(0.05)
        return False

    def close(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self.flush(timeout=timeout)
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=timeout)

    def __enter__(self) -> 'ZenuxClient':
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def report_audit_events(self, events: Sequence[Mapping[str, Any]]) -> None:
        if not events:
            return

        payload = {'events': [dict(event) for event in events]}
        self._enqueue('api/audit', payload)

    def report_audit_event(self, event: Mapping[str, Any]) -> None:
        self.report_audit_events([event])

    def report_findings(self, findings: Sequence[Any], *, session_id: str | None = None, target_id: str | None = None) -> None:
        if not findings:
            return

        payload = {'findings': [self._finding_payload(finding, session_id=session_id, target_id=target_id) for finding in findings]}
        self._enqueue('api/ingest/findings', payload)

    def report_finding(self, finding: Any, *, session_id: str | None = None, target_id: str | None = None) -> None:
        self.report_findings([finding], session_id=session_id, target_id=target_id)

    def evaluate_policy(
        self,
        *,
        hook: str,
        event: Mapping[str, Any],
        actor_id: str | None = None,
        actor_type: str = 'service',
        requested_by: str | None = None,
        asset_id: str | None = None,
        linked_case_id: str | None = None,
        linked_finding_id: str | None = None,
        expires_in_minutes: int | None = None,
        registries: Mapping[str, Sequence[str]] | None = None,
        environment: str | None = None,
    ) -> dict[str, Any] | None:
        if not self.is_configured:
            self._warn_once_missing_config()
            return None

        url = f"{self.endpoint}/api/policy-evaluations"
        payload: dict[str, Any] = {
            'hook': hook,
            'actorId': actor_id or self.agent_id,
            'actorType': actor_type,
            'event': dict(event),
        }
        if requested_by:
            payload['requestedBy'] = requested_by
        if asset_id:
            payload['assetId'] = asset_id
        if linked_case_id:
            payload['linkedCaseId'] = linked_case_id
        if linked_finding_id:
            payload['linkedFindingId'] = linked_finding_id
        if expires_in_minutes is not None:
            payload['expiresInMinutes'] = expires_in_minutes
        if registries:
            payload['registries'] = {key: list(values) for key, values in registries.items()}
        if environment:
            payload['environment'] = environment

        try:
            response = self._transport(url, payload, self._build_headers(), self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            self._warn(f'policy evaluation failed: {exc}')
            return None

        if response is None:
            return None

        if not getattr(response, 'ok', True):
            status = getattr(response, 'status_code', 'unknown')
            text = truncate_text(str(getattr(response, 'text', '')), 200)
            self._warn(f'policy evaluation returned HTTP {status}{f": {text}" if text else ""}')
            return None

        payload = _extract_json(response)
        return payload if isinstance(payload, dict) else None

    def session(
        self,
        *,
        agent_id: str | None = None,
        repo: str | None = None,
        work_item_id: str | None = None,
        source: str | None = None,
        session_id: str | None = None,
    ) -> 'AgentSession':
        from .session import AgentSession

        return AgentSession(
            self,
            agent_id=agent_id,
            repo=repo,
            work_item_id=work_item_id,
            source=source,
            session_id=session_id,
        )

    def monitor(self, *args: Any, **kwargs: Any):
        from .monitor import monitor

        return monitor(self, *args, **kwargs)

    def _finding_payload(
        self,
        finding: Any,
        *,
        session_id: str | None = None,
        target_id: str | None = None,
    ) -> dict[str, Any]:
        if hasattr(finding, 'to_dict') and callable(getattr(finding, 'to_dict')):
            source = finding.to_dict()
        elif isinstance(finding, Mapping):
            source = dict(finding)
        else:
            raise TypeError('report_finding expects a Finding or mapping-like object')

        def as_str_list(value: Any) -> list[str]:
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                return [normalize_text(entry, 200) for entry in value if isinstance(entry, (str, int, float))]
            return []

        title = _safe_text(source.get('title') or 'Agent finding', 200)
        description = _safe_text(source.get('description') or source.get('evidence') or source.get('summary') or title, 800)
        summary = _safe_text(source.get('summary') or description, 400)
        remediation_steps = as_str_list(source.get('remediationSteps') or source.get('remediation_steps'))

        toxicity = source.get('toxicity')
        if not isinstance(toxicity, Mapping):
            toxicity = compute_toxicity(20, 20, 20, 20).to_dict()

        risk_score = source.get('riskScore')
        if not isinstance(risk_score, (int, float)):
            risk_score = int(toxicity.get('overall', 0)) if isinstance(toxicity, Mapping) else 0

        class_name = str(source.get('className') or source.get('class_name') or 'prompt_injection')
        trace_session_id = session_id or self.session_id
        external_key = ':'.join(
            [
                self.agent_id,
                self.repo or 'no-repo',
                self.work_item_id or 'no-work-item',
                trace_session_id,
            ]
        )

        payload = {
            'title': title,
            'className': class_name,
            'severity': str(source.get('severity') or 'medium'),
            'source': str(source.get('source') or self.source),
            'summary': summary,
            'description': description,
            'remediationSteps': remediation_steps or ['Review the agent session and redact any leaked material.'],
            'affectedTarget': str(source.get('affectedTarget') or target_id or self.repo or self.agent_id),
            'owaspCategory': str(source.get('owaspCategory') or 'LLM01'),
            'mitreAtlasTechnique': str(source.get('mitreAtlasTechnique') or 'AML.T0049 - Autonomous Impact'),
            'riskScore': int(risk_score),
            'toxicity': dict(toxicity) if isinstance(toxicity, Mapping) else compute_toxicity(20, 20, 20, 20).to_dict(),
            'traceId': trace_session_id,
            'externalKey': external_key,
            'tags': as_str_list(source.get('tags')) or [self.source, self.agent_id],
        }

        return payload
