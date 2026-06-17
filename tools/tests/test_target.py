"""Unit tests for native toolkit target safety validation.

Tool name: target validation tests
OWASP coverage: LLM01-LLM10
MITRE mapping: mocked AML validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from lib.target import validate_target


class TargetTests(unittest.TestCase):
    def test_rejects_private_and_metadata_targets(self) -> None:
        for target in [
            "192.168.1.22",
            "10.0.0.9",
            "127.0.0.1",
            "169.254.169.254",
            "https://metadata.google.internal/computeMetadata/v1/",
        ]:
            with self.assertRaises(ValueError):
                validate_target(target)

    def test_accepts_public_targets(self) -> None:
        self.assertEqual(validate_target("https://api.example.com/v1/chat/completions"), "api.example.com")
        self.assertEqual(validate_target("8.8.8.8"), "8.8.8.8")

    def test_allow_internal_bypasses_the_safety_gate(self) -> None:
        with patch.dict(os.environ, {"ALLOW_INTERNAL": "1"}):
            self.assertEqual(validate_target("192.168.1.15"), "192.168.1.15")


if __name__ == "__main__":
    unittest.main()

