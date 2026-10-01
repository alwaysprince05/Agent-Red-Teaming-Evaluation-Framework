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
- [x] 76 pytest tests, ruff-clean, GitHub Actions CI, Dockerfile

## Stretch goals (planned)

1. Adaptive attack generation / mutation (fuzzing-style broadening of coverage).
2. Indirect injection via simulated retrieval & tool-output pipelines.
3. Memory & cross-session contamination tests.
4. Web dashboard for historical scores, trends and regressions.
5. CI/CD evaluation quality gate with thresholds (partially supported via CLI exit codes).
6. Plugin architecture for custom attacks, evaluators, policies and adapters.
7. Benchmark adapters for public safety datasets where licensing permits.
8. Object-store backend for run artifacts.
