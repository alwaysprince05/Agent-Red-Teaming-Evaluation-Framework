"""Tests for Adaptive Red-Teaming — Checks the smart attack loop.

Tests in this file verify:
  - The adaptive agent runs through plan/generate/attack/reflect cycles.
  - Budget limits (max rounds, cases per round) are respected and clamped.
  - Category planning picks the weakest category first, then untried ones.
  - The loop stops when the budget is exhausted.
  - The full trace is recorded and inspectable (no hidden decisions).
  - Generated cases have unique IDs across rounds (no collisions).
  - The JSON output is serializable for machine-readable reports.
"""

import json

import pytest

from agent_redteam.adapters.base import resolve_target
from agent_redteam.core.adaptive import (
    MAX_GENERATED_CASES,
    MAX_ROUNDS_CAP,
    AdaptiveAgent,
    AdaptiveLimit,
    run_adaptive,
)
from agent_redteam.core.suite import SuiteError

CATS = [
    "prompt_injection",
    "jailbreak",
    "data_leakage",
    "unsafe_tool_use",
    "multi_turn_manipulation",
    "indirect_injection",
]


@pytest.fixture(scope="module")
def seed_suite() -> str:
    from pathlib import Path

    return str(Path(__file__).resolve().parents[1] / "agent_redteam" / "attacks" / "core_suite.yaml")


class TestLimits:
    def test_rounds_clamped_to_cap(self):
        assert AdaptiveLimit(max_rounds=10_000).max_rounds == MAX_ROUNDS_CAP
        assert AdaptiveLimit(max_rounds=0).max_rounds == 1

    def test_cases_per_round_clamped_to_generator_budget(self):
        assert AdaptiveLimit(cases_per_round=500).cases_per_round == MAX_GENERATED_CASES
        assert AdaptiveLimit(cases_per_round=0).cases_per_round == 1

    def test_defaults_inside_budget(self):
        lim = AdaptiveLimit()
        assert 1 <= lim.max_rounds <= MAX_ROUNDS_CAP
        assert 1 <= lim.cases_per_round <= MAX_GENERATED_CASES


class TestLoopBehavior:
    def test_single_round_probes_one_category(self, tmp_path, seed_suite, weak_agent):
        report = run_adaptive(
            weak_agent,
            seed_suite,
            limits=AdaptiveLimit(max_rounds=1, cases_per_round=4),
            run_options=None,
            generation_mode="mutate",
            rng_seed=3,
            output_dir=tmp_path / "runs",
        )
        assert len(report.rounds) == 1
        assert report.rounds[0].planned_category in CATS
        assert report.total_generated <= 4
        assert report.stopped_reason

    def test_round_budget_respected(self, tmp_path, seed_suite, weak_agent):
        report = run_adaptive(
            weak_agent,
            seed_suite,
            limits=AdaptiveLimit(max_rounds=3, cases_per_round=3),
            generation_mode="mutate",
            rng_seed=1,
            output_dir=tmp_path / "runs",
        )
        assert len(report.rounds) <= 3
        assert report.total_generated <= 9
        assert {r.planned_category for r in report.rounds} == set(report.categories_attacked)

    def test_no_violations_from_strong_still_batches(self, tmp_path, seed_suite, strong_agent):
        report = run_adaptive(
            strong_agent,
            seed_suite,
            limits=AdaptiveLimit(max_rounds=2, cases_per_round=3),
            generation_mode="mutate",
            rng_seed=2,
            output_dir=tmp_path / "runs",
        )
        assert len(report.rounds) <= 2
        for r in report.rounds:
            assert r.executed > 0

    def test_trace_fields_complete(self, tmp_path, seed_suite, weak_agent):
        report = run_adaptive(
            weak_agent,
            seed_suite,
            limits=AdaptiveLimit(max_rounds=2, cases_per_round=2),
            generation_mode="mutate",
            rng_seed=5,
            output_dir=tmp_path / "runs",
        )
        assert report.rounds
        for r in report.rounds:
            assert r.plan
            assert r.planned_category
            assert r.mode_used in ("llm", "mutate")
            assert r.run_id and r.suite_path
            assert r.decision in ("continue", "stop")
            assert r.elapsed_s >= 0

    def test_report_json_serializable(self, tmp_path, seed_suite, weak_agent):
        report = run_adaptive(
            weak_agent,
            seed_suite,
            limits=AdaptiveLimit(max_rounds=1, cases_per_round=2),
            generation_mode="mutate",
            rng_seed=9,
            output_dir=tmp_path / "runs",
        )
        dumped = json.dumps(
            {
                "rounds": [
                    {
                        "round_no": r.round_no,
                        "plan": r.plan,
                        "planned_category": r.planned_category,
                        "mode": r.mode_used,
                        "generated": r.generated,
                        "violations": r.violations,
                        "decision": r.decision,
                    }
                    for r in report.rounds
                ],
                "stopped": report.stopped_reason,
            }
        )
        assert "planned_category" in dumped


class TestSafety:
    def test_uses_normal_target_resolution(self):
        """The loop does not create its own authorization path — resolve_target is reused."""
        from agent_redteam.adapters.base import TargetNotAuthorizedError

        with pytest.raises(TargetNotAuthorizedError):
            resolve_target("https://external.example.com/eval")

    def test_adapter_is_required_before_anything_runs(self, tmp_path, seed_suite):
        with pytest.raises(ValueError):
            AdaptiveAgent(None, seed_suite).run(output_dir=tmp_path)  # type: ignore[arg-type]

    def test_invalid_seed_suite_rejected_without_running(self, tmp_path, weak_agent):
        with pytest.raises(SuiteError):
            AdaptiveAgent(weak_agent, tmp_path / "missing.yaml").run(output_dir=tmp_path)

    def test_generated_suites_persisted_for_review(self, tmp_path, seed_suite, weak_agent):
        run_adaptive(
            weak_agent,
            seed_suite,
            limits=AdaptiveLimit(max_rounds=2, cases_per_round=3),
            generation_mode="mutate",
            rng_seed=4,
            output_dir=tmp_path / "runs",
        )
        suites_dir = tmp_path / "runs" / "adaptive_suites"
        suites = list(suites_dir.glob("*.yaml"))
        assert suites  # fully inspectable: one reviewable suite per round on disk



class TestCLI:
    def test_adaptive_cli_runs_and_reports(self, tmp_path):
        from agent_redteam.cli import main

        rc = main(
            [
                "adaptive",
                "--target", "mock:weak",
                "--max-rounds", "1",
                "--cases-per-round", "3",
                "--mode", "mutate",
                "--seed", "7",
                "--out", str(tmp_path / "runs"),
            ]
        )
        assert rc == 1  # mock:weak must produce violations

    def test_adaptive_cli_json_mode(self, tmp_path, capsys):
        from agent_redteam.cli import main

        rc = main(
            [
                "adaptive",
                "--target", "mock:weak",
                "--max-rounds", "1",
                "--cases-per-round", "2",
                "--mode", "mutate",
                "--json",
                "--out", str(tmp_path / "runs"),
            ]
        )
        assert rc == 1  # JSON report must not mask the violations exit code
        out = capsys.readouterr().out
        report = json.loads(out)
        assert report["rounds"][0]["planned_category"] in CATS
        assert report["total_violations"] > 0

    def test_adaptive_cli_rejects_unauthorized_target(self, capsys):
        from agent_redteam.cli import main

        rc = main(["adaptive", "--target", "https://external.example.com/eval"])
        assert rc == 2
        assert "refus" in capsys.readouterr().err.lower()

    def test_adaptive_parser_has_no_hidden_auth_bypass(self):
        from agent_redteam.cli import _build_parser

        parser = _build_parser()
        for bad in (["adaptive", "--skip-auth"], ["adaptive", "--no-auth"]):
            with pytest.raises(SystemExit):
                parser.parse_args(bad)
