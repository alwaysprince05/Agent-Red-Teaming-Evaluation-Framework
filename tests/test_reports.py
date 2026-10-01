from pathlib import Path

import pytest

from agent_redteam.core.runner import RunOptions, execute_run
from agent_redteam.reports.generate import generate_findings_csv, generate_markdown_report


@pytest.fixture()
def weak_summary(tmp_path, weak_agent, suite_path):
    rid, _summary, _results, _records = execute_run(
        suite_path, weak_agent, RunOptions(output_dir=tmp_path), run_id="run-rep"
    )
    return rid, tmp_path


class TestReports:
    def test_markdown_report_contents(self, weak_summary):
        rid, out_dir = weak_summary
        from agent_redteam.core.schemas import RunSummary

        summary = RunSummary.model_validate_json((out_dir / rid / "summary.json").read_text())
        out = generate_markdown_report(summary, [], Path(out_dir) / "report.md")
        text = out.read_text(encoding="utf-8")
        assert "# Agent Red-Team Evaluation Report" in text
        assert "## Summary Metrics" in text
        assert "## Findings" in text
        assert "Attack success rate" in text
        assert "prompt_injection" in text

    def test_csv_report_contents(self, weak_summary):
        rid, out_dir = weak_summary
        from agent_redteam.core.schemas import RunSummary

        summary = RunSummary.model_validate_json((out_dir / rid / "summary.json").read_text())
        out = generate_findings_csv(summary, Path(out_dir) / "findings.csv")
        text = out.read_text(encoding="utf-8")
        lines = text.strip().splitlines()
        assert lines[0].startswith("finding_id,test_id,category,severity")
        assert len(lines) == 1 + len(summary.findings)

    def test_report_generation_fast(self, weak_summary):
        import time

        rid, out_dir = weak_summary
        from agent_redteam.core.schemas import RunSummary

        summary = RunSummary.model_validate_json((out_dir / rid / "summary.json").read_text())
        start = time.time()
        generate_markdown_report(summary, [], Path(out_dir) / "bench.md")
        assert time.time() - start < 2.0
