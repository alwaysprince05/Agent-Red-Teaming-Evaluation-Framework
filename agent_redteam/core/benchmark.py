"""Benchmark harness (PRD 3.3 performance): throughput, latency, artifact and report timing."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from agent_redteam.adapters.base import AgentAdapter
from agent_redteam.core.engine import EngineConfig, ExecutionEngine
from agent_redteam.core.suite import load_suite


@dataclass
class BenchmarkResult:
    suite_path: str
    target: str
    iterations: int
    total_cases: int
    wall_time_s: float
    cases_per_second: float
    avg_latency_ms: float
    p95_latency_ms: float
    timeout_rate: float
    error_rate: float
    tool_call_count: int
    artifact_size_bytes: int = 0
    report_time_s: float | None = None
    notes: list[str] = field(default_factory=list)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return ordered[idx]


def benchmark_suite(
    suite_path: str | Path,
    adapter: AgentAdapter,
    *,
    iterations: int = 3,
    timeout_s: float = 15.0,
    rate_limit_s: float = 0.0,
) -> BenchmarkResult:
    """Run the suite repeatedly and measure throughput, latency and failure rates."""
    cases = load_suite(suite_path)
    engine = ExecutionEngine(
        adapter,
        EngineConfig(timeout_s=timeout_s, rate_limit_s=rate_limit_s),
    )

    all_latencies: list[float] = []
    timeouts = 0
    errors = 0
    tool_calls = 0
    total = 0

    start = time.time()
    for _ in range(max(1, iterations)):
        for case in cases:
            rec = engine.run_case("benchmark", case)
            total += 1
            if rec.latency_ms is not None:
                all_latencies.append(float(rec.latency_ms))
            if rec.status.value == "timeout":
                timeouts += 1
            elif rec.status.value == "error":
                errors += 1
            tool_calls += len(rec.tool_calls)
    wall = time.time() - start

    return BenchmarkResult(
        suite_path=str(suite_path),
        target=getattr(adapter, "url", f"{adapter.name}:{getattr(adapter, 'profile', '')}"),
        iterations=max(1, iterations),
        total_cases=total,
        wall_time_s=round(wall, 3),
        cases_per_second=round(total / wall, 3) if wall > 0 else 0.0,
        avg_latency_ms=round(sum(all_latencies) / len(all_latencies), 3) if all_latencies else 0.0,
        p95_latency_ms=round(_percentile(all_latencies, 95), 3),
        timeout_rate=round(timeouts / total, 4) if total else 0.0,
        error_rate=round(errors / total, 4) if total else 0.0,
        tool_call_count=tool_calls,
    )


def measure_report_generation(summary_path: str | Path, out_dir: str | Path) -> float:
    """Time Markdown + CSV report generation from an existing run summary (seconds)."""
    from agent_redteam.core.schemas import RunSummary
    from agent_redteam.reports.generate import generate_findings_csv, generate_markdown_report

    summary = RunSummary.model_validate_json(Path(summary_path).read_text(encoding="utf-8"))
    start = time.time()
    generate_markdown_report(summary, [], Path(out_dir) / "bench-report.md")
    generate_findings_csv(summary, Path(out_dir) / "bench-findings.csv")
    return round(time.time() - start, 3)


def measure_artifact_size(run_dir: str | Path) -> int:
    return sum(p.stat().st_size for p in Path(run_dir).glob("*.json"))
