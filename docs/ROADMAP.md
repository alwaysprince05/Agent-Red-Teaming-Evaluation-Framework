# Project Roadmap & Status

## Shipped (v0.1.0)

- [x] Pydantic schemas: TestCase, Policy, ExecutionRecord, EvaluationResult, Finding, RunSummary
- [x] Versioned YAML attack library — 13 cases across 6 categories
- [x] Adapter interface + `mock:weak` / `mock:strong` + HTTP adapter
- [x] Safe-by-default target authorization (loopback open, external needs explicit consent + allowlist)
- [x] Execution engine: per-case timeout, rate limit, per-case isolation
- [x] Deterministic evaluator + optional LLM-as-judge (temperature 0, structured verdicts)
- [x] Severity + evidence-backed findings with reproduction & remediation
- [x] Metrics: attack success rate, violation rate, pass rate, per-category
- [x] Baseline comparison: regressions, improvements, metric deltas
- [x] Markdown + CSV reports
- [x] CLI (`run`, `compare`, `report`, `list-attacks`) with CI-gate exit codes
- [x] FastAPI service with synchronous authorization and background runs
- [x] 145 pytest tests, ruff-clean, GitHub Actions CI, Dockerfile
- [x] Benchmark harness + measured performance report (docs/PERFORMANCE.md)

### Delivered in v1.0.0 (post-release additions)

- [x] HTML dashboard: history, trends, findings browser (`agent-redteam dashboard`)
- [x] Final PRD deliverables report (docs/FINAL_REPORT.md)
- [x] GitHub release v1.0.0

# Stretch goals (planned)

1. ~~Adaptive attack generation / mutation (fuzzing-style broadening of coverage).~~
   Shipped: `agent-redteam generate` (LLM proposals when `AGENT_REDTEAM_LLM_*` configured,
   else deterministic mutations of the seed suite), every case gated through `TestCase`
   validation with server-side derived policies and a ≤50/request budget.
   Still planned on top: LLM-judge adjudication of obfuscated-input non-refusals.
   Shipped on top of that: `agent-redteam adaptive` — the closed-loop red-teaming agent
   (plan → generate → attack → reflect with a ReAct-style trace), deterministic weakest-
   category planner, hard budgets (≤20 rounds, ≤50 cases/round, unique ids across rounds),
   persisted per-round suites, and the same CI exit-code contract as `run`.
2. Indirect injection via simulated retrieval & tool-output pipelines.
3. Memory & cross-session contamination tests.
4. Web dashboard for historical scores, trends and regressions.
5. CI/CD evaluation quality gate with thresholds (partially supported via CLI exit codes).
6. Plugin architecture for custom attacks, evaluators, policies and adapters.
7. Benchmark adapters for public safety datasets where licensing permits.
8. Object-store backend for run artifacts.
