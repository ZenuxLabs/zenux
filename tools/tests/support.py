"""Zenux Scan Toolkit test support helpers.

Tool name: test module loader
OWASP coverage: LLM01-LLM10
MITRE mapping: mocked coverage validation only
Safety disclaimer: For authorized testing only. These tests use mocks only and must not touch live systems.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def load_tool_module(filename: str, module_name: str) -> ModuleType:
    tools_dir = Path(__file__).resolve().parent.parent
    module_path = tools_dir / filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

