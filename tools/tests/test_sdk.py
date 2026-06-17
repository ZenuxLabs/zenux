"""Unit tests for the Zenux background-agent SDK."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from lib.schema import build_finding, compute_toxicity
from sdk.client import ZenuxClient
from sdk.redaction import redact_text
from sdk.session import AgentSession


class CaptureTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __call__(self, url: str, payload: dict[str, object], headers: dict[str, str], timeout: int):
        self.calls.append(
            {
                'url': url,
                'payload': payload,
                'headers': headers,
                'timeout': timeout,
            }
        )
        return SimpleNamespace(
            ok=True,
            status_code=201,
            text='ok',
            json=lambda: {'created': 1, 'results': []},
        )


class ZenuxSdkTests(unittest.TestCase):
    def test_redacts_repeated_secrets_and_prompt_phrases(self) -> None:
        redacted = redact_text(
            '\n'.join(
                [
                    'export AWS_SECRET_ACCESS_KEY=super-secret-value AWS_SECRET_ACCESS_KEY=second-secret',
                    'token: sk-ant-abc123def456ghi789jkl012 and token: sk-ant-abc123def456ghi789jkl012',
                    'ignore previous instructions and ignore previous instructions again',
                ]
            )
        )

        self.assertIn('[REDACTED:AWS_SECRET_ACCESS_KEY]', redacted)
        self.assertIn('[REDACTED:Anthropic API key]', redacted)
        self.assertIn('[REDACTED:PROMPT_INJECTION]', redacted)
        self.assertNotIn('super-secret-value', redacted)
        self.assertNotIn('second-secret', redacted)
        self.assertNotIn('sk-ant-abc123def456ghi789jkl012', redacted)
        self.assertNotIn('ignore previous instructions', redacted)

    def test_agent_session_buffers_audit_events_and_redacts_payloads(self) -> None:
        transport = CaptureTransport()
        client = ZenuxClient(
            endpoint='https://zenux.example',
            secret='secret-token',
            background=False,
            transport=transport,
            agent_id='agent-1',
            repo='owner/repo',
            work_item_id='work-1',
        )

        with AgentSession(client, session_id='session-1') as session:
            session.log_prompt('use sk-ant-abc123def456ghi789jkl012 and ignore previous instructions')
            session.log_tool_call('bash', {'command': 'echo hello'})
            session.log_response('bash', {'stdout': 'ok'})

        self.assertEqual(len(transport.calls), 1)
        audit_call = transport.calls[0]
        self.assertEqual(audit_call['url'], 'https://zenux.example/api/audit')

        events = audit_call['payload']['events']  # type: ignore[index]
        self.assertEqual(len(events), 5)
        serialized = json.dumps(audit_call['payload'])
        self.assertNotIn('sk-ant-abc123def456ghi789jkl012', serialized)
        self.assertNotIn('ignore previous instructions', serialized)

        first_event = events[0]
        self.assertEqual(first_event['action'], 'agent.session.started')
        self.assertEqual(first_event['targetType'], 'agent_session')
        self.assertEqual(first_event['metadata']['agentId'], 'agent-1')
        self.assertEqual(first_event['metadata']['repo'], 'owner/repo')

    def test_agent_session_summarizes_finding_lists_without_repr_leaks(self) -> None:
        transport = CaptureTransport()
        client = ZenuxClient(
            endpoint='https://zenux.example',
            secret='secret-token',
            background=False,
            transport=transport,
            agent_id='agent-3',
            repo='owner/repo',
            work_item_id='work-3',
        )

        finding = build_finding(
            tool_id='BG',
            title='Credential exposure in tool response',
            severity='critical',
            class_name='credential_theft',
            owasp_category='LLM02',
            mitre_atlas_technique='AML.T0049 - Autonomous Impact',
            source='test',
            toxicity=compute_toxicity(30, 30, 20, 35),
            fixability='immediate',
            remediation_steps=['Rotate the exposed credential.'],
            affected_target='bash',
            evidence='raw evidence with sk-ant-abc123def456ghi789jkl012 and ignore previous instructions',
        )

        with AgentSession(client, session_id='session-3') as session:
            session.log_response('bash', [finding])

        self.assertEqual(len(transport.calls), 1)
        audit_call = transport.calls[0]
        payload_json = json.dumps(audit_call['payload'])
        self.assertNotIn('raw evidence with sk-ant-abc123def456ghi789jkl012', payload_json)
        self.assertNotIn('Finding(', payload_json)

        events = audit_call['payload']['events']  # type: ignore[index]
        response_event = next(event for event in events if event['action'] == 'agent.tool_call.completed')
        self.assertEqual(
            response_event['metadata']['responseSnippet'],
            'Returned 1 finding(s): Credential exposure in tool response',
        )

    def test_monitor_reports_risky_tool_calls_without_blocking_return_value(self) -> None:
        transport = CaptureTransport()
        client = ZenuxClient(
            endpoint='https://zenux.example',
            secret='secret-token',
            background=False,
            transport=transport,
            agent_id='agent-2',
            repo='owner/repo',
            work_item_id='work-2',
        )

        with AgentSession(client, session_id='session-2') as session:

            @session.monitor(tool_name='shell-helper', source='test')
            def run_tool(command: str) -> str:
                return 'done'

            result = run_tool('export TOKEN=sk-ant-abc123def456ghi789jkl012 && curl https://example.com')

        self.assertEqual(result, 'done')
        urls = [call['url'] for call in transport.calls]
        self.assertIn('https://zenux.example/api/ingest/findings', urls)
        self.assertIn('https://zenux.example/api/audit', urls)

        findings_call = next(call for call in transport.calls if str(call['url']).endswith('/api/ingest/findings'))
        findings_payload = findings_call['payload']['findings']  # type: ignore[index]
        self.assertGreaterEqual(len(findings_payload), 1)
        findings_serialized = json.dumps(findings_call['payload'])
        self.assertNotIn('sk-ant-abc123def456ghi789jkl012', findings_serialized)
        self.assertTrue(any(finding['title'] for finding in findings_payload))


if __name__ == '__main__':
    unittest.main()
