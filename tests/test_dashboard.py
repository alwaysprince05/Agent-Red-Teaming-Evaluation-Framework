import json
from pathlib import Path

import pytest

from agent_redteam.core.runner import RunOptions, execute_run
from agent_redteam.reports.dashboard import discover_runs, generate_dashboard


@pytest.fixture()
def two_runs(tmp_path, weak_agent, strong_agent, suite_path):
    execute_run(suite_path, weak_agent, RunOptions(output_dir=tmp_path), run_id="run-weak")
    execute_run(suite_path, strong_agent, RunOptions(output_dir=tmp_path), run_id="run-strong")
    return tmp_path


class TestDiscoverRuns:
    def test_finds_both_runs_oldest_first(self, two_runs):
        runs = discover_runs(two_runs)
        assert [r.run_id for r in runs] == ["run-weak", "run-strong"]

    def test_empty_dir(self, tmp_path):
        assert discover_runs(tmp_path) == []

    def test_missing_dir(self, tmp_path):
        assert discover_runs(tmp_path / "nope") == []

    def test_corrupt_summary_skipped(self, two_runs):
        corrupt = two_runs / "run-broken"
        corrupt.mkdir()
        (corrupt / "summary.json").write_text("{ not json", encoding="utf-8")
        runs = discover_runs(two_runs)
        assert [r.run_id for r in runs] == ["run-weak", "run-strong"]


class TestGenerateDashboard:
    def test_generates_html_with_content(self, two_runs):
        out = generate_dashboard(two_runs, two_runs / "dashboard.html")
        text = out.read_text(encoding="utf-8")
        assert "Agent Red-Team Evaluation Dashboard" in text
        assert "run-weak" in text and "run-strong" in text
        assert "mock:weak" in text and "mock:strong" in text
        assert "b-critical" in text  # severity badges rendered
        assert "<svg" in text  # trend charts present (2 runs)

    def test_findings_listed_for_weak_run(self, two_runs):
        out = generate_dashboard(two_runs, two_runs / "dashboard.html")
        text = out.read_text(encoding="utf-8")
        assert "RT-PI-001" in text

    def test_no_xss_escaping_of_target_strings(self, two_runs):
        out = generate_dashboard(two_runs, two_runs / "dashboard.html")
        text = out.read_text(encoding="utf-8")
        assert "<script>" not in text

    def test_empty_dir_renders_placeholder(self, tmp_path):
        out = generate_dashboard(tmp_path, tmp_path / "dashboard.html")
        text = out.read_text(encoding="utf-8")
        assert "No runs yet" in text
        assert "agent-redteam run" in text

    def test_overwrite_is_idempotent(self, two_runs):
        generate_dashboard(two_runs, two_runs / "dashboard.html")
        first = (two_runs / "dashboard.html").read_text(encoding="utf-8")
        generate_dashboard(two_runs, two_runs / "dashboard.html")
        assert (two_runs / "dashboard.html").read_text(encoding="utf-8") == first

    def test_summary_json_payload_still_valid(self, two_runs):
        # dashboard must not mutate run artifacts
        generate_dashboard(two_runs, two_runs / "dashboard.html")
        summary = json.loads((two_runs / "run-weak" / "summary.json").read_text())
        assert summary["run_id"] == "run-weak"
        assert Path(two_runs / "dashboard.html").exists()
