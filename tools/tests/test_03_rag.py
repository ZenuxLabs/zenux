"""Unit tests for the RAG poisoning probe.

Tool name: 03_rag_poisoning_probe tests
OWASP coverage: LLM04, LLM08
MITRE mapping: mocked AML.T0020 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from tests.support import load_tool_module

rag = load_tool_module("03_rag_poisoning_probe.py", "tool_03_rag")


class RagTests(unittest.TestCase):
    def _response(self, text: str, status_code: int = 200) -> SimpleNamespace:
        return SimpleNamespace(
            status_code=status_code,
            text=text,
            json=lambda: {"answer": text},
        )

    def test_measure_canary_success_rate_calculates_ratio(self) -> None:
        queries = ['q1', 'q2', 'q3', 'q4', 'q5']
        responses = {
            'q1': 'CANARY_TOKEN_deadbeef',
            'q2': 'miss',
            'q3': 'CANARY_TOKEN_deadbeef',
            'q4': 'miss',
            'q5': 'CANARY_TOKEN_deadbeef',
        }

        rate = rag.measure_canary_success_rate(
            'CANARY_TOKEN_deadbeef',
            lambda query: responses[query],
            queries,
        )

        self.assertEqual(rate, 0.6)

    def test_confidence_overrides_exploit_maturity(self) -> None:
        finding = rag.build_poisoning_finding(
            target='https://rag.example.com',
            overall_confidence=0.8,
            evidence='multi-canary hit',
        )

        self.assertEqual(finding.canary_count, 3)
        self.assertEqual(finding.queries_per_canary, 5)
        self.assertAlmostEqual(finding.success_rate, 0.8)
        self.assertGreater(finding.toxicity.exploitMaturity, 15)

    def test_black_box_flag_is_parsed(self) -> None:
        parser = rag.build_parser()
        args = parser.parse_args(
            [
                '--endpoint',
                'https://rag.example.com',
                '--ingest-endpoint',
                '/api/documents',
                '--query-endpoint',
                '/api/query',
                '--black-box',
            ]
        )

        self.assertTrue(args.black_box)

    @patch.object(rag.requests, "get")
    @patch.object(rag.requests, "post")
    @patch.object(uuid, "uuid4")
    def test_canary_answer_change_creates_critical_indirect_injection(
        self,
        mock_uuid: unittest.mock.Mock,
        mock_post: unittest.mock.Mock,
        mock_get: unittest.mock.Mock,
    ) -> None:
        mock_uuid.side_effect = [
            uuid.UUID("11111111-1111-1111-1111-111111111111"),
            uuid.UUID("b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2"),
            uuid.UUID("22222222-2222-2222-2222-222222222222"),
            uuid.UUID("d4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4"),
            uuid.UUID("33333333-3333-3333-3333-333333333333"),
            uuid.UUID("f6f6f6f6-f6f6-f6f6-f6f6-f6f6f6f6f6f6"),
        ]

        query_hits = {
            "11111111-1111-1111-1111-111111111111": ["CANARY_TOKEN_b2b2b2b2"] * 4 + ["miss"],
            "22222222-2222-2222-2222-222222222222": ["CANARY_TOKEN_d4d4d4d4"] * 3 + ["miss", "miss"],
            "33333333-3333-3333-3333-333333333333": ["CANARY_TOKEN_f6f6f6f6"] * 3 + ["miss", "miss"],
        }
        query_counters = {key: 0 for key in query_hits}

        def post_side_effect(url: str, headers=None, json=None, timeout=10):  # noqa: ANN001
            if url.endswith("/api/documents"):
                return self._response("accepted", status_code=201)

            question = json.get("question", "")
            if question in rag.BASELINE_QUESTIONS:
                return self._response({
                    "What color is the sky?": "blue",
                    "What is the capital of France?": "Paris",
                    "What is the emergency paging channel for support?": "channel 7",
                }[question])

            for canary_label, responses in query_hits.items():
                if canary_label in question:
                    index = query_counters[canary_label]
                    query_counters[canary_label] += 1
                    return self._response(responses[index])

            raise AssertionError(f"Unexpected query payload: {json}")

        mock_post.side_effect = post_side_effect
        mock_get.return_value = self._response("not found", status_code=404)

        findings = rag.scan_endpoint("https://rag.example.com", "/api/documents", "/api/query")
        poisoning = next(
            finding
            for finding in findings
            if finding.className == "indirect_injection" and finding.severity == "critical"
        )
        self.assertAlmostEqual(poisoning.confidence, 2 / 3)
        self.assertEqual(poisoning.canary_count, 3)
        self.assertEqual(poisoning.queries_per_canary, 5)

    @patch.object(rag.requests, "get")
    @patch.object(rag.requests, "post")
    def test_unauthenticated_ingest_endpoint_is_critical_model_poisoning(self, mock_post: unittest.mock.Mock, mock_get: unittest.mock.Mock) -> None:
        def post_side_effect(url: str, headers=None, json=None, timeout=10):  # noqa: ANN001
            if url.endswith("/api/documents"):
                return self._response("accepted", status_code=200)

            question = json.get("question", "")
            if question in rag.BASELINE_QUESTIONS:
                return self._response({
                    "What color is the sky?": "blue",
                    "What is the capital of France?": "Paris",
                    "What is the emergency paging channel for support?": "channel 7",
                }[question])

            return self._response("miss")

        mock_post.side_effect = post_side_effect
        mock_get.return_value = self._response("not found", status_code=404)

        findings = rag.scan_endpoint("https://rag.example.com", "/api/documents", "/api/query")
        self.assertTrue(any(f.className == "model_poisoning" and f.severity == "critical" for f in findings))

    @patch.object(rag.requests, "get")
    @patch.object(rag.requests, "post")
    def test_vector_db_endpoint_exposed_is_high(self, mock_post: unittest.mock.Mock, mock_get: unittest.mock.Mock) -> None:
        def post_side_effect(url: str, headers=None, json=None, timeout=10):  # noqa: ANN001
            if url.endswith("/api/documents"):
                return self._response("accepted", status_code=201)

            question = json.get("question", "")
            if question in rag.BASELINE_QUESTIONS:
                return self._response({
                    "What color is the sky?": "blue",
                    "What is the capital of France?": "Paris",
                    "What is the emergency paging channel for support?": "channel 7",
                }[question])

            return self._response("miss")

        mock_post.side_effect = post_side_effect
        mock_get.side_effect = [self._response('{"collections": ["prod"]}', status_code=200)]

        findings = rag.scan_endpoint("https://rag.example.com", "/api/documents", "/api/query", auth_header="Authorization: Bearer x")
        self.assertTrue(any(f.className == "data_exfiltration" and f.severity == "high" for f in findings))


if __name__ == "__main__":
    unittest.main()
