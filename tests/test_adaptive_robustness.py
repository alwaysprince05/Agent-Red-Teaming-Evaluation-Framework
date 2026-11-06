"""Adaptive loop robustness with an unreliable LLM generator (offline).

A small model sometimes returns unparseable or invalid proposals. In auto mode the
loop must fall back to deterministic mutations for that round and keep going; an
explicit mode must not silently change.
"""

import pytest

from agent_redteam.core import generator as gen_module
from agent_redteam.core.adaptive import AdaptiveAgent, AdaptiveLimit
from agent_redteam.core.generator import GeneratorError, validate_proposals
from agent_redteam.core.runner import RunOptions


@pytest.fixture()
def llm_env(monkeypatch):
    monkeypatch.setenv("AGENT_REDTEAM_LLM_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("AGENT_REDTEAM_LLM_MODEL", "fake")


def make_agent(adapter, suite_path, tmp_path, mode, rounds=2):
    return AdaptiveAgent(
        adapter,
        suite_path,
        limits=AdaptiveLimit(max_rounds=rounds, cases_per_round=2),
        run_options=RunOptions(rate_limit_s=0.0, output_dir=tmp_path),
        generation_mode=mode,
        planner_mode="heuristic",
    )


def test_auto_falls_back_to_mutations_when_llm_fails(llm_env, monkeypatch, weak_agent, suite_path, tmp_path):
    def broken(*_a, **_k):
        raise GeneratorError("LLM generator returned unparseable output")

    monkeypatch.setattr(gen_module, "propose_cases_llm", broken)
    report = make_agent(weak_agent, suite_path, tmp_path, "auto").run(output_dir=tmp_path)
    assert len(report.rounds) == 2 and report.total_executed > 0
    assert all(r.mode_used == "mutate" for r in report.rounds)
    assert all(any("fell back to mutations" in e for e in r.rejected_reasons) for r in report.rounds)


def test_auto_falls_back_when_all_llm_proposals_invalid(
    llm_env, monkeypatch, weak_agent, suite_path, tmp_path
):
    bad = [{"objective": "x", "turns": [{"role": "assistant", "content": "hi"}]}]
    monkeypatch.setattr(gen_module, "propose_cases_llm", lambda *_a, **_k: bad)
    report = make_agent(weak_agent, suite_path, tmp_path, "auto", rounds=1).run(output_dir=tmp_path)
    r = report.rounds[0]
    assert r.mode_used == "mutate" and r.executed > 0
    assert any("all invalid" in e for e in r.rejected_reasons)


def test_explicit_llm_mode_does_not_fall_back(llm_env, monkeypatch, weak_agent, suite_path, tmp_path):
    def broken(*_a, **_k):
        raise GeneratorError("down")

    monkeypatch.setattr(gen_module, "propose_cases_llm", broken)
    report = make_agent(weak_agent, suite_path, tmp_path, "llm").run(output_dir=tmp_path)
    assert len(report.rounds) == 1 and report.rounds[0].decision == "stop"
    assert "generation failed" in report.stopped_reason


def test_validation_errors_are_one_line():
    _valid, errors = validate_proposals(
        [
            {
                "objective": "probe it",
                "turns": [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}],
            }
        ],
        expected_category="jailbreak",
    )
    assert len(errors) == 1 and "\n" not in errors[0]
    assert "turns.1.role" in errors[0]


def test_report_target_includes_profile(weak_agent, suite_path, tmp_path):
    report = make_agent(weak_agent, suite_path, tmp_path, "mutate", rounds=1).run(output_dir=tmp_path)
    assert report.target == "mock:weak"
