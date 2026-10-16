"""Test Configuration — Shared fixtures used by all test files.

This file is automatically loaded by pytest before running any tests.
It provides reusable "fixtures" (pre-built objects) that test functions can use:

  - suite_path: Path to the built-in core attack suite (13 test cases).
  - weak_agent: A mock agent that is deliberately vulnerable (fails all tests).
  - strong_agent: A mock agent that is hardened (passes all tests).

It also adds the project root to the Python path so imports work correctly.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_redteam.adapters.mock_agent import MockAgent  # noqa: E402


@pytest.fixture()
def suite_path() -> str:
    return str(ROOT / "agent_redteam" / "attacks" / "core_suite.yaml")


@pytest.fixture()
def weak_agent() -> MockAgent:
    return MockAgent(profile="weak")


@pytest.fixture()
def strong_agent() -> MockAgent:
    return MockAgent(profile="strong")
