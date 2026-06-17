"""Unit tests for native toolkit Kali wrappers.

Tool name: Kali wrapper tests
OWASP coverage: LLM03, LLM06, LLM07, LLM10
MITRE mapping: mocked AML validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from lib.kali import gobuster_dir, nmap_service_scan, parse_nmap_open_ports


class KaliTests(unittest.TestCase):
    def test_nmap_parser_extracts_open_ports(self) -> None:
        output = """
80/tcp open  http    nginx 1.24.0
443/tcp open  ssl/http nginx 1.24.0
11434/tcp open  http    Ollama
"""
        self.assertEqual(parse_nmap_open_ports(output), [(80, "http    nginx 1.24.0"), (443, "ssl/http nginx 1.24.0"), (11434, "http    Ollama")])

    @patch("lib.kali.subprocess.run")
    def test_gobuster_wrapper_returns_discovered_paths(self, mock_run: unittest.mock.Mock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["gobuster"],
            returncode=0,
            stdout="/models (Status: 200)\n/config.json (Status: 200)\n",
            stderr="",
        )
        self.assertEqual(
            gobuster_dir("https://example.com", "/tmp/wordlist.txt"),
            ["/models", "/config.json"],
        )

    @patch("lib.kali.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=60))
    def test_timeout_is_enforced(self, mock_run: unittest.mock.Mock) -> None:
        self.assertEqual(nmap_service_scan("api.example.com"), "")
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 60)


if __name__ == "__main__":
    unittest.main()
