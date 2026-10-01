import pytest

from agent_redteam.adapters.mock_agent import MockAgent
from agent_redteam.core.engine import EngineConfig, ExecutionEngine
from agent_redteam.core.schemas import ExecStatus
from agent_redteam.core.suite import load_suite
from agent_redteam.evaluators.deterministic import evaluate_case


@pytest.fixture()
def engine_cases(suite_path):
    return load_suite(suite_path)


class TestEngine:
    def test_runs_all_cases(self, weak_agent, engine_cases):
        engine = ExecutionEngine(weak_agent, EngineConfig(rate_limit_s=0))
        records = [engine.run_case("run-test", c) for c in engine_cases]
        assert len(records) == len(engine_cases)
        assert all(r.status is ExecStatus.ok for r in records)

    def test_timeout_is_reported(self, engine_cases, monkeypatch):
        class SlowAgent(MockAgent):
            def send(self, turns):
                import time

                time.sleep(5)
                return super().send(turns)

        engine = ExecutionEngine(SlowAgent(profile="weak"), EngineConfig(timeout_s=0.2, rate_limit_s=0))
        record = engine.run_case("run-test", engine_cases[0])
        assert record.status is ExecStatus.timeout
        assert "timed out" in (record.response_error or "")

    def test_per_case_isolation(self, weak_agent, engine_cases):
        engine = ExecutionEngine(weak_agent, EngineConfig(rate_limit_s=0))
        r1 = engine.run_case("run-a", engine_cases[0])
        r2 = engine.run_case("run-b", engine_cases[0])
        assert r1.run_id != r2.run_id
        assert r1.turns_sent == r2.turns_sent


class TestDeterministicEvaluator:
    def test_weak_violates_injection_case(self, weak_agent, engine_cases):
        case = next(c for c in engine_cases if c.id == "RT-PI-001")
        engine = ExecutionEngine(weak_agent, EngineConfig(rate_limit_s=0))
        rec = engine.run_case("run-eval", case)
        res = evaluate_case(case, rec)
        assert res.violated is True
        assert res.score == 0.0
        assert res.evidence

    def test_strong_passes_injection_case(self, strong_agent, engine_cases):
        case = next(c for c in engine_cases if c.id == "RT-PI-001")
        engine = ExecutionEngine(strong_agent, EngineConfig(rate_limit_s=0))
        rec = engine.run_case("run-eval", case)
        res = evaluate_case(case, rec)
        assert res.violated is False
        assert res.score == 1.0

    def test_weak_violates_tool_allowlist(self, weak_agent, engine_cases):
        case = next(c for c in engine_cases if c.id == "RT-TU-001")
        engine = ExecutionEngine(weak_agent, EngineConfig(rate_limit_s=0))
        rec = engine.run_case("run-eval", case)
        res = evaluate_case(case, rec)
        assert res.violated is True
        assert any("send_email" in ev.detail for ev in res.evidence)

    def test_strong_passes_tool_allowlist(self, strong_agent, engine_cases):
        case = next(c for c in engine_cases if c.id == "RT-TU-001")
        engine = ExecutionEngine(strong_agent, EngineConfig(rate_limit_s=0))
        rec = engine.run_case("run-eval", case)
        res = evaluate_case(case, rec)
        assert res.violated is False

    def test_timeout_case_is_error_not_violation(self, strong_agent, engine_cases, monkeypatch):
        case = engine_cases[0]
        engine = ExecutionEngine(strong_agent, EngineConfig(rate_limit_s=0))

        class Clock:
            @staticmethod
            def time():
                return 0.0

        rec = engine.run_case("run-eval", case)
        rec.mark(ExecStatus.timeout, error="target timed out after 15s")
        res = evaluate_case(case, rec)
        assert res.status.value == "error"
        assert res.violated is False

    def test_error_response_marked_error(self, engine_cases):
        class FailingAgent(MockAgent):
            def send(self, turns):
                from agent_redteam.core.schemas import AgentResponse

                return AgentResponse(error="connection refused")

        engine = ExecutionEngine(FailingAgent(profile="weak"), EngineConfig(rate_limit_s=0))
        rec = engine.run_case("run-eval", engine_cases[0])
        res = evaluate_case(engine_cases[0], rec)
        assert res.status.value == "error"
