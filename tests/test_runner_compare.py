import json

import pytest

from agent_redteam.core.compare import (
    ComparisonError,
    compare_from_artifacts,
    compare_runs,
    load_results_for_run,
)
from agent_redteam.core.runner import RunOptions, execute_run


@pytest.fixture()
def weak_run(tmp_path, weak_agent, suite_path):
    rid, summary, results, records = execute_run(
        suite_path, weak_agent, RunOptions(output_dir=tmp_path), run_id="run-weak"
    )
    return rid, tmp_path


@pytest.fixture()
def strong_run(tmp_path, strong_agent, suite_path):
    rid, summary, results, records = execute_run(
        suite_path, strong_agent, RunOptions(output_dir=tmp_path), run_id="run-strong"
    )
    return rid, tmp_path


class TestExecuteRun:
    def test_weak_run_produces_violations_and_artifacts(self, weak_run):
        rid, out_dir = weak_run
        run_dir = out_dir / rid
        assert (run_dir / "summary.json").exists()
        assert (run_dir / "results.json").exists()
        assert (run_dir / "records.json").exists()
        summary = json.loads((run_dir / "summary.json").read_text())
        assert summary["metrics"]["violations"] > 0
        assert len(summary["findings"]) == summary["metrics"]["violations"]

    def test_strong_run_passes_all(self, strong_run):
        rid, out_dir = strong_run
        summary = json.loads((out_dir / rid / "summary.json").read_text())
        assert summary["metrics"]["violations"] == 0
        assert summary["metrics"]["errors"] == 0
        assert summary["findings"] == []

    def test_all_six_categories_covered(self, weak_run):
        rid, out_dir = weak_run
        metrics = json.loads((out_dir / rid / "summary.json").read_text())["metrics"]
        assert set(metrics["by_category"]) == {
            "prompt_injection",
            "jailbreak",
            "data_leakage",
            "unsafe_tool_use",
            "multi_turn_manipulation",
            "indirect_injection",
        }
        # every category must have at least one violation on the weak target
        assert all(cat["violations"] > 0 for cat in metrics["by_category"].values())


class TestCompare:
    def test_weak_to_strong_shows_improvements(self, weak_run, strong_run):
        rid_w, out_w = weak_run
        rid_s, out_s = strong_run
        report = compare_from_artifacts(out_w / rid_w, out_s / rid_s)
        assert len(report.improvements) > 0
        assert report.regressions == []
        assert report.metric_deltas["attack_success_rate"] < 0

    def test_strong_to_weak_shows_regressions(self, weak_run, strong_run):
        rid_w, out_w = weak_run
        rid_s, out_s = strong_run
        report = compare_from_artifacts(out_s / rid_s, out_w / rid_w)
        assert len(report.regressions) > 0
        assert report.improvements == []

    def test_compare_run_dirs(self, weak_run, strong_run):
        rid_w, out_w = weak_run
        rid_s, out_s = strong_run
        report = compare_runs(
            load_results_for_run(out_w, rid_w),
            load_results_for_run(out_s, rid_s),
            rid_w,
            rid_s,
        )
        assert len(report.improvements) > 0

    def test_missing_artifact_raises(self, tmp_path):
        with pytest.raises(ComparisonError):
            compare_from_artifacts(tmp_path / "a", tmp_path / "b")
