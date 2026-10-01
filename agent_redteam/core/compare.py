"""Baseline comparison between two evaluation runs."""

from __future__ import annotations

from pathlib import Path

from agent_redteam.core.schemas import (
    SEVERITY_ORDER,
    ComparisonReport,
    EvaluationResult,
    RegressionItem,
    RunSummary,
)


class ComparisonError(ValueError):
    """Raised when run artifacts are missing or unreadable."""


def _load_jsonl(path: Path) -> list[EvaluationResult]:
    if not path.exists():
        raise ComparisonError(f"missing run artifact: {path}")
    items: list[EvaluationResult] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(EvaluationResult.model_validate_json(line))
        except Exception as exc:
            raise ComparisonError(f"invalid result line in {path}: {exc}") from exc
    return items


def _load_summary(run_dir: Path) -> RunSummary:
    p = run_dir / "summary.json"
    if not p.exists():
        raise ComparisonError(f"missing run summary: {p}")
    try:
        return RunSummary.model_validate_json(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ComparisonError(f"invalid run summary {p}: {exc}") from exc


def load_results_for_run(runs_dir: str | Path, run_id: str) -> list[EvaluationResult]:
    return _load_jsonl(Path(runs_dir) / run_id / "results.json")


def load_summary_for_run(runs_dir: str | Path, run_id: str) -> RunSummary:
    return _load_summary(Path(runs_dir) / run_id)


def _item(res: EvaluationResult, detail: str) -> RegressionItem:
    return RegressionItem(test_id=res.test_id, category=res.category, kind="regression", detail=detail)


def compare_runs(
    baseline_results: list[EvaluationResult],
    current_results: list[EvaluationResult],
    baseline_run_id: str,
    current_run_id: str,
    *,
    baseline_summary: RunSummary | None = None,
    current_summary: RunSummary | None = None,
) -> ComparisonReport:
    base = {r.test_id: r for r in baseline_results}
    cur = {r.test_id: r for r in current_results}

    regressions: list[RegressionItem] = []
    improvements: list[RegressionItem] = []
    unchanged_violations: list[RegressionItem] = []

    for test_id, c in cur.items():
        b = base.get(test_id)
        if b is None:
            if c.violated:
                regressions.append(
                    RegressionItem(
                        test_id=test_id,
                        category=c.category,
                        kind="regression",
                        detail=f"new case violated in current run (severity {c.severity.value})",
                    )
                )
            continue
        b_bad = b.status.value == "violated"
        c_bad = c.status.value == "violated"
        if b_bad and not c_bad:
            improvements.append(
                RegressionItem(
                    test_id=test_id,
                    category=c.category,
                    kind="improvement",
                    detail=f"previously violated ({b.severity.value}), now safe",
                )
            )
        elif not b_bad and c_bad:
            regressions.append(
                RegressionItem(
                    test_id=test_id,
                    category=c.category,
                    kind="regression",
                    detail=f"previously safe, now violates (severity {c.severity.value})",
                )
            )
        elif b_bad and c_bad:
            worse = SEVERITY_ORDER.get(c.severity, 0) > SEVERITY_ORDER.get(b.severity, 0)
            unchanged_violations.append(
                RegressionItem(
                    test_id=test_id,
                    category=c.category,
                    kind="still_violating",
                    detail="still violating"
                    + (f", severity escalated {b.severity.value} -> {c.severity.value}" if worse else ""),
                )
            )

    metric_deltas: dict[str, float] = {}
    if baseline_summary and current_summary:
        mb, mc = baseline_summary.metrics, current_summary.metrics
        metric_deltas = {
            "attack_success_rate": round(mc.attack_success_rate - mb.attack_success_rate, 4),
            "violation_rate": round(mc.violation_rate - mb.violation_rate, 4),
            "pass_rate": round(mc.pass_rate - mb.pass_rate, 4),
        }

    return ComparisonReport(
        baseline_run_id=baseline_run_id,
        current_run_id=current_run_id,
        regressions=regressions,
        improvements=improvements,
        unchanged_violations=unchanged_violations,
        metric_deltas=metric_deltas,
    )


def compare_run_dirs(runs_dir: str | Path, baseline_id: str, current_id: str) -> ComparisonReport:
    baseline = load_results_for_run(runs_dir, baseline_id)
    current = load_results_for_run(runs_dir, current_id)
    return compare_runs(
        baseline,
        current,
        baseline_id,
        current_id,
        baseline_summary=load_summary_for_run(runs_dir, baseline_id),
        current_summary=load_summary_for_run(runs_dir, current_id),
    )


def compare_from_artifacts(baseline_dir: str | Path, current_dir: str | Path) -> ComparisonReport:
    """Compare two run directories directly (no runs/ index required)."""
    b_dir, c_dir = Path(baseline_dir), Path(current_dir)
    b_id = _run_id_from(b_dir)
    c_id = _run_id_from(c_dir)
    return compare_runs(
        _load_jsonl(b_dir / "results.json"),
        _load_jsonl(c_dir / "results.json"),
        b_id,
        c_id,
        baseline_summary=_load_summary(b_dir),
        current_summary=_load_summary(c_dir),
    )


def _run_id_from(run_dir: Path) -> str:
    summary = _load_summary(run_dir)
    return summary.run_id
