import json

import pytest

from agent_redteam.adapters.mock_agent import MockAgent
from agent_redteam.core.engine import EngineConfig, ExecutionEngine
from agent_redteam.core.suite import load_suite
from agent_redteam.evaluators import llm_judge
from agent_redteam.evaluators.llm_judge import (
    _parse_verdict,
    build_judge_prompt,
    evaluate_case_llm_judge,
    judge_configured,
)


@pytest.fixture()
def judged_case_record(suite_path):
    cases = load_suite(suite_path)
    case = next(c for c in cases if c.id == "RT-PI-001")
    engine = ExecutionEngine(MockAgent(profile="weak"), EngineConfig(rate_limit_s=0))
    rec = engine.run_case("run-judge", case)
    return case, rec


class TestConfigDetection:
    def test_not_configured_by_default(self, monkeypatch):
        for var in ("AGENT_REDTEAM_LLM_BASE_URL", "AGENT_REDTEAM_LLM_MODEL"):
            monkeypatch.delenv(var, raising=False)
        assert judge_configured() is False

    def test_configured_when_env_set(self, monkeypatch):
        monkeypatch.setenv("AGENT_REDTEAM_LLM_BASE_URL", "http://127.0.0.1:9/v1")
        monkeypatch.setenv("AGENT_REDTEAM_LLM_MODEL", "test-model")
        assert judge_configured() is True


class TestVerdictParsing:
    def test_plain_json(self):
        v = _parse_verdict('{"violated": true, "severity": "high", "rationale": "leaked", "score": 0.0}')
        assert v is not None and v["violated"] is True

    def test_json_in_prose(self):
        raw = (
            'Sure! Here is my verdict: '
            '{"violated": false, "severity": "low", "rationale": "refused", "score": 1.0}'
        )
        v = _parse_verdict(raw)
        assert v is not None and v["violated"] is False

    def test_garbage_returns_none(self):
        assert _parse_verdict("no json here at all") is None


class TestUnconfiguredBehavior:
    def test_unconfigured_returns_error_not_pass(self, judged_case_record):
        case, rec = judged_case_record
        res = evaluate_case_llm_judge(case, rec)
        assert res.status.value == "error"
        assert res.violated is False
        assert "not configured" in res.rationale


class TestConfiguredBehavior:
    def _with_env(self, monkeypatch):
        monkeypatch.setenv("AGENT_REDTEAM_LLM_BASE_URL", "http://127.0.0.1:9/v1")
        monkeypatch.setenv("AGENT_REDTEAM_LLM_MODEL", "test-model")
        monkeypatch.setenv("AGENT_REDTEAM_LLM_API_KEY", "test-key")

    def test_judge_violation(self, judged_case_record, monkeypatch):
        self._with_env(monkeypatch)
        case, rec = judged_case_record

        class FakeResp:
            def raise_for_status(self):
                return None

            def json(self):
                content = json.dumps(
                    {"violated": True, "severity": "critical", "rationale": "leaked secrets", "score": 0.0}
                )
                return {"choices": [{"message": {"content": content}}]}

        monkeypatch.setattr(
            llm_judge.httpx, "post", lambda *a, **kw: FakeResp(), raising=True
        )
        res = evaluate_case_llm_judge(case, rec)
        assert res.status.value == "violated"
        assert res.severity.value == "critical"

    def test_judge_http_failure_is_error(self, judged_case_record, monkeypatch):
        import httpx as _httpx

        self._with_env(monkeypatch)
        case, rec = judged_case_record

        def boom(*a, **kw):
            raise _httpx.ConnectError("connection refused")

        monkeypatch.setattr(llm_judge.httpx, "post", boom, raising=True)
        res = evaluate_case_llm_judge(case, rec)
        assert res.status.value == "error"
        assert "judge call failed" in res.rationale


class TestPromptBuilder:
    def test_prompt_contains_policy_and_response(self, judged_case_record):
        case, rec = judged_case_record
        prompt = build_judge_prompt(case, rec)
        assert "Adversarial objective" in prompt
        assert "must be a refusal" in prompt
        assert "DB_PASS" in rec.response_text and "Agent response" in prompt
