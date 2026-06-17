"""Unit tests for the ML model static file scanner.

Tool name: 12_ml_model_static_scanner tests
OWASP coverage: LLM03
MITRE mapping: mocked AML.T0010 validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.support import load_tool_module

scanner = load_tool_module("12_ml_model_static_scanner.py", "tool_12_ml_scanner")


class PickleScanTests(unittest.TestCase):
    """Tests for pickle byte-level analysis."""

    def test_pickle_v4_with_os_system_is_critical(self) -> None:
        data = b"\x80\x04\x95" + b"\x00" * 10 + b"cos\nsystem\n" + b"\x52"
        issues = scanner.scan_pickle_bytes(data, "model.pkl")
        self.assertTrue(any(i["severity"] == "critical" for i in issues))
        self.assertTrue(any("os" in i["detail"] and "system" in i["detail"] for i in issues))

    def test_pickle_v4_with_subprocess_is_critical(self) -> None:
        data = b"\x80\x04\x95" + b"\x00" * 10 + b"csubprocess\nPopen\n"
        issues = scanner.scan_pickle_bytes(data, "model.pkl")
        self.assertTrue(any(i["severity"] == "critical" for i in issues))

    def test_pickle_v4_reduce_global_is_high(self) -> None:
        data = b"\x80\x04\x95" + b"\x00" * 10 + b"cGLOBAL" + b"\x52"
        issues = scanner.scan_pickle_bytes(data, "model.pkl")
        self.assertTrue(any(
            i["type"] in ("pickle_rce_callable", "pickle_reduce_global") for i in issues
        ))

    def test_plain_pickle_v4_is_high(self) -> None:
        data = b"\x80\x04\x95" + b"\x00" * 50
        issues = scanner.scan_pickle_bytes(data, "model.pkl")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "pickle_unsafe_format")
        self.assertEqual(issues[0]["severity"], "high")

    def test_plain_pickle_v3_is_high(self) -> None:
        data = b"\x80\x03" + b"\x00" * 50
        issues = scanner.scan_pickle_bytes(data, "model.pkl")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "pickle_unsafe_format")

    def test_zip_with_data_pkl_is_medium(self) -> None:
        data = b"PK\x03\x04" + b"\x00" * 20 + b"data.pkl" + b"\x00" * 50
        issues = scanner.scan_pickle_bytes(data, "model.pt")
        self.assertTrue(any(i["type"] == "pickle_unsafe_format" for i in issues))

    def test_safetensors_returns_no_issues(self) -> None:
        data = b'\x00\x00\x00\x10safetensors-header'
        issues = scanner.scan_pickle_bytes(data, "model.safetensors")
        self.assertEqual(len(issues), 0)

    def test_non_pickle_returns_empty(self) -> None:
        data = b"just random text data here"
        issues = scanner.scan_pickle_bytes(data, "model.txt")
        self.assertEqual(len(issues), 0)


class CompressionBypassTests(unittest.TestCase):
    """Tests for 7z/bzip2 bypass detection."""

    def test_7z_magic_is_critical(self) -> None:
        data = b"\x37\x7a\xbc\xaf" + b"\x00" * 50
        issues = scanner.scan_compression_bypass(data, "model.7z")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "critical")
        self.assertIn("7z", issues[0]["detail"])

    def test_bzip2_magic_is_critical(self) -> None:
        data = b"\x42\x5a\x68" + b"9" + b"\x00" * 50
        issues = scanner.scan_compression_bypass(data, "model.bz2")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "critical")
        self.assertIn("bzip2", issues[0]["detail"])

    def test_normal_zip_no_bypass(self) -> None:
        data = b"PK\x03\x04" + b"\x00" * 50
        issues = scanner.scan_compression_bypass(data, "archive.zip")
        self.assertEqual(len(issues), 0)


class ConfigScanTests(unittest.TestCase):
    """Tests for model config file analysis."""

    def test_trust_remote_code_true_is_high(self) -> None:
        config = json.dumps({"trust_remote_code": True, "architectures": ["GPT2"]}).encode()
        issues = scanner.scan_config_file(config, "config.json")
        self.assertTrue(any(i["type"] == "trust_remote_code" for i in issues))
        self.assertTrue(any(i["severity"] == "high" for i in issues))

    def test_trust_remote_code_false_no_issue(self) -> None:
        config = json.dumps({"trust_remote_code": False}).encode()
        issues = scanner.scan_config_file(config, "config.json")
        trust_issues = [i for i in issues if i["type"] == "trust_remote_code"]
        self.assertEqual(len(trust_issues), 0)

    def test_auto_map_detected(self) -> None:
        config = json.dumps({"auto_map": {"AutoModel": "custom_model.py"}}).encode()
        issues = scanner.scan_config_file(config, "config.json")
        self.assertTrue(any(i["type"] == "custom_code_mapping" for i in issues))

    def test_invalid_json_returns_empty(self) -> None:
        issues = scanner.scan_config_file(b"not json at all", "config.json")
        self.assertEqual(len(issues), 0)


class ModelCardTests(unittest.TestCase):
    """Tests for model card completeness checks."""

    def test_missing_model_card_is_medium(self) -> None:
        issues = scanner.scan_model_card(None, "test-model")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "missing_model_card")
        self.assertEqual(issues[0]["severity"], "medium")

    def test_short_model_card_is_medium(self) -> None:
        issues = scanner.scan_model_card("Short", "test-model")
        self.assertTrue(any(i["type"] == "missing_model_card" for i in issues))

    def test_complete_model_card_no_issues(self) -> None:
        card = (
            "# Model Card\n\n## License\nMIT\n\n## Intended Use\nResearch\n\n"
            "## Limitation\nNot for production\n\n## Bias\nSee paper for details."
        )
        issues = scanner.scan_model_card(card, "test-model")
        self.assertEqual(len(issues), 0)

    def test_incomplete_model_card_is_low(self) -> None:
        card = "# Model Card\n\n## License\nMIT\n\nThis is a long enough model card content to pass the minimum check."
        issues = scanner.scan_model_card(card, "test-model")
        incomplete = [i for i in issues if i["type"] == "incomplete_model_card"]
        self.assertEqual(len(incomplete), 1)
        self.assertEqual(incomplete[0]["severity"], "low")


class LocalDirectoryScanTests(unittest.TestCase):
    """Tests for local directory scanning integration."""

    def test_scan_directory_with_pickle_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pickle_path = Path(tmpdir) / "model.pkl"
            pickle_path.write_bytes(b"\x80\x04\x95" + b"\x00" * 50)
            readme_path = Path(tmpdir) / "README.md"
            readme_path.write_text(
                "# Model\n## License\nMIT\n## Intended Use\nTest\n"
                "## Limitation\nNone\n## Bias\nNone",
                encoding="utf-8",
            )

            findings = scanner.scan_local_directory(tmpdir)
            self.assertTrue(len(findings) >= 1)
            pickle_findings = [f for f in findings if "pickle" in f.title.lower()]
            self.assertTrue(len(pickle_findings) >= 1)

    def test_scan_nonexistent_directory(self) -> None:
        findings = scanner.scan_local_directory("/nonexistent/path/xyz")
        self.assertEqual(len(findings), 1)
        self.assertIn("does not exist", findings[0].title)

    def test_scan_directory_with_7z_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bypass_path = Path(tmpdir) / "model.7z"
            bypass_path.write_bytes(b"\x37\x7a\xbc\xaf" + b"\x00" * 50)
            readme_path = Path(tmpdir) / "README.md"
            readme_path.write_text(
                "# Model\n## License\nMIT\n## Intended Use\nTest\n"
                "## Limitation\nNone\n## Bias\nNone",
                encoding="utf-8",
            )

            findings = scanner.scan_local_directory(tmpdir)
            seven_z = [f for f in findings if "7z" in f.title.lower()]
            self.assertTrue(len(seven_z) >= 1)

    def test_scan_directory_with_dangerous_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(
                json.dumps({"trust_remote_code": True}),
                encoding="utf-8",
            )
            readme_path = Path(tmpdir) / "README.md"
            readme_path.write_text(
                "# Model\n## License\nMIT\n## Intended Use\nTest\n"
                "## Limitation\nNone\n## Bias\nNone",
                encoding="utf-8",
            )

            findings = scanner.scan_local_directory(tmpdir)
            trust_findings = [f for f in findings if "trust_remote_code" in f.title.lower()]
            self.assertTrue(len(trust_findings) >= 1)


class HuggingFaceURITests(unittest.TestCase):
    """Tests for HuggingFace URI parsing."""

    def test_invalid_uri_format(self) -> None:
        findings = scanner.scan_target("huggingface://invalid")
        self.assertEqual(len(findings), 1)
        self.assertIn("Invalid", findings[0].title)

    @patch.object(scanner, "_hf_get_readme", return_value=None)
    @patch.object(scanner, "_hf_download_file")
    @patch.object(scanner, "_hf_list_files")
    def test_hf_repo_with_pickle(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        _mock_readme: MagicMock,
    ) -> None:
        mock_list.return_value = [{"rfilename": "model.pkl"}]
        mock_download.return_value = b"\x80\x04\x95" + b"\x00" * 50

        findings = scanner.scan_target("huggingface://test-org/test-model")
        self.assertTrue(len(findings) >= 1)


if __name__ == "__main__":
    unittest.main()
