"""Test Configuration — Shared fixtures used by all test files.

This file is automatically loaded by pytest before running any tests.
It provides reusable "fixtures" (pre-built objects) that test functions can use:

  - suite_path: Path to the built-in core attack suite (13 test cases).
  - weak_agent: A mock agent that is deliberately vulnerable (fails all tests).
  - strong_agent: A mock agent that is hardened (passes all tests).
  - _hermetic_env (autouse): clears AGENT_REDTEAM_* variables so no test can reach a
    real model by accident. Live tests opt in with RUN_LIVE_LLM=1 and use LIVE_ENV.

It also adds the project root to the Python path so imports work correctly.
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_redteam.adapters.mock_agent import MockAgent  # noqa: E402

#: The developer's real settings, captured before tests clear them (used by live tests only).
LIVE_ENV = {k: v for k, v in os.environ.items() if k.startswith("AGENT_REDTEAM_")}


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in LIVE_ENV:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture()
def suite_path() -> str:
    return str(ROOT / "agent_redteam" / "attacks" / "core_suite.yaml")


@pytest.fixture()
def weak_agent() -> MockAgent:
    return MockAgent(profile="weak")


@pytest.fixture()
def strong_agent() -> MockAgent:
    return MockAgent(profile="strong")
