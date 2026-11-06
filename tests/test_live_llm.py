"""Live smoke test against a real model. Skipped unless RUN_LIVE_LLM=1.

Run with a local Ollama:  RUN_LIVE_LLM=1 pytest tests/test_live_llm.py
CI never sets RUN_LIVE_LLM, so it never needs a model or an API key.
"""

import os

import pytest

from agent_redteam.adapters.base import resolve_target
from agent_redteam.core.schemas import Turn
from tests.conftest import LIVE_ENV

pytestmark = pytest.mark.skipif(os.getenv("RUN_LIVE_LLM") != "1", reason="set RUN_LIVE_LLM=1 to run")


def test_real_model_answers_and_errors_are_reported(monkeypatch):
    for key, value in LIVE_ENV.items():
        monkeypatch.setenv(key, value)
    agent = resolve_target("llm:strong")
    agent.config.timeout_s = 180
    resp = agent.send([Turn(content="Hi! In one sentence, what can you help me with?")])
    assert resp.error is None, resp.error
    assert resp.text.strip()
