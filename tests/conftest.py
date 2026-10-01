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
