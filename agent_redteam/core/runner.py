"""Run orchestration: suite -> executions -> evaluations -> findings -> metrics -> artifacts."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from agent_redteam.adapters.base import AgentAdapter
from agent_redteam.core.engine import EngineConfig, ExecutionEngine
from agent_redteam.core.schemas import (
    EvaluationResult,
    Finding,
    RunSummary,
    SuiteMetrics,
    TestCase,
    new_finding_id,
    new_run_id,
)
from agent_redteam.evaluators.deterministic import evaluate_case
from agent_redteam.evaluators.llm_judge import evaluate_case_llm_judge, judge_configured

_SEVERITY_REMEDIATION = {
    "prompt_injection": "Harden the system prompt with explicit override-resistance instructions; "
    "separate trusted instructions from untrusted user content.",
    "jailbreak": "Reinforce persona boundaries and add restriction-removal refusals; test with "
    "known jailbreak corpora before release.",
    "data_leakage": "Never place real secrets in model context; enforce secret-scanning output "
    "filters and credential vaulting.",
    "unsafe_tool_use": "Enforce per-conversation tool allowlists and confirm dangerous actions "
    "with the operator.",
    "multi_turn_manipulation": "Evaluate conversations, not single prompts; add multi-turn "
    "consistency checks and trust-decay heuristics.",
    "indirect_injection": "Treat retrieved content and tool outputs as untrusted data, never as "
    "instructions; wrap and label external content.",
}

_FALLBACK_REMEDIATION = "Review the flagged response, harden the relevant policy, and re-run the suite."


@dataclass
class RunOptions:
    use_llm_judge: bool = False  # deterministic evaluator is always run
    judge_fallback_to_deterministic: bool = True
    rate_limit_s: float = 0.2
    timeout_s: float = 15.0
    max_turns: int = 20
    output_dir: Path = field(default_factory=lambda: Path("runs"))


def _avg(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 3) if values else None


def _build_finding(case: TestCase, result: EvaluationResult, record) -> Finding:
    category = case.category.value
    repro = (
        f"Re-run case {case.id} against the same target "
        f"(agent-redteam run --suite <suite> --target <target>). "
        f"Attack turns: {len(record.turns_sent)}; response began with: "
        f"{(record.response_text or record.response_error or '')[:120]!r}"
    )
    return Finding(
        id=new_finding_id(),
        test_id=case.id,
        category=category,
        title=f"{category}: {case.objective[:80]}",
        severity=result.severity,
        reproduction=repro,
        remediation=_SEVERITY_REMEDIATION.get(category, _FALLBACK_REMEDIATION),
        evidence=result.evidence,
    )


def _aggregate_metrics(
    cases: list[TestCase],
    records: dict[str, object],
    results: list[EvaluationResult],
) -> SuiteMetrics:
    total = len(cases)
    by_cat: dict[str, dict[str, float]] = {}
    for case in cases:
        by_cat.setdefault(case.category.value, {"total": 0, "violations": 0, "errors": 0})
        by_cat[case.category.value]["total"] += 1
    for r in results:
        cat = by_cat.setdefault(r.category, {"total": 0, "violations": 0, "errors": 0})
        if r.status.value == "violated":
            cat["violations"] += 1
        elif r.status.value == "error":
            cat["errors"] += 1
    for cat in by_cat.values():
        judged = cat["total"] - cat["errors"]
        cat["violation_rate"] = round(cat["violations"] / judged, 4) if judged else 0.0

    violations = sum(1 for r in results if r.status.value == "violated")
    errors = sum(1 for r in results if r.status.value == "error")
    executed = sum(1 for r in results if r.status.value != "error")
    latencies = [
        rec.latency_ms
        for rec in records.values()
        if getattr(rec, "latency_ms", None) is not None
    ]
    return SuiteMetrics(
        total_cases=total,
        executed=executed,
        violations=violations,
        errors=errors,
        attack_success_rate=round(violations / executed, 4) if executed else 0.0,
        violation_rate=round(violations / total, 4) if total else 0.0,
        pass_rate=round((executed - violations) / total, 4) if total else 0.0,
        avg_latency_ms=_avg([float(x) for x in latencies]),
        by_category=by_cat,
    )


def execute_run(
    suite_path: str | Path,
    adapter: AgentAdapter,
    options: RunOptions | None = None,
    *,
    run_id: str | None = None,
) -> tuple[str, RunSummary, list[EvaluationResult], list]:
    """Run the full pipeline and persist artifacts. Returns (run_id, summary, results, records)."""
    from agent_redteam.core.suite import load_suite

    opts = options or RunOptions()
    rid = run_id or new_run_id()
    cases: list[TestCase] = load_suite(suite_path)

    engine = ExecutionEngine(
        adapter,
        EngineConfig(timeout_s=opts.timeout_s, rate_limit_s=opts.rate_limit_s, max_turns=opts.max_turns),
    )
    records = {case.id: engine.run_case(rid, case) for case in cases}

    results: list[EvaluationResult] = []
    for case in cases:
        record = records[case.id]
        if opts.use_llm_judge and judge_configured():
            r = evaluate_case_llm_judge(case, record)
            if r.status.value == "error" and opts.judge_fallback_to_deterministic:
                r = evaluate_case(case, record)
        else:
            r = evaluate_case(case, record)
        results.append(r)

    findings = [
        _build_finding(case, r, records[case.id])
        for case, r in zip(cases, results, strict=True)
        if r.violated
    ]
    metrics = _aggregate_metrics(cases, records, results)
    summary = RunSummary(
        run_id=rid,
        created_at=time.time(),
        suite=str(suite_path),
        target=getattr(adapter, "url", f"{adapter.name}:{getattr(adapter, 'profile', '')}"),
        metrics=metrics,
        findings=findings,
    )

    out_dir = Path(opts.output_dir) / rid
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    (out_dir / "results.json").write_text(
        "\n".join(r.model_dump_json() for r in results), encoding="utf-8"
    )
    (out_dir / "records.json").write_text(
        "\n".join(rec.model_dump_json() for rec in records.values()), encoding="utf-8"
    )
    return rid, summary, results, list(records.values())
