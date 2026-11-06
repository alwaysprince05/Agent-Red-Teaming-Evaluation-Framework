# Final Project Report — PRD Deliverables Mapping

**Project:** Agent Red-Teaming & Evaluation Framework
**Student:** Prince Kumar Maurya (Roll No 240410700103, 2026, Gen AI track, Group G132)
**Mentor:** Anurag Sarkar
**Version:** 2.0.0 · **Repo:** github.com/alwaysprince05/Agent-Red-Teaming-Evaluation-Framework

Verification state at v2.0.0: **196 pytest tests passing** (+1 opt-in live test), `ruff` clean, GitHub Actions CI
green on Python 3.11/3.12/3.13 (lint + tests + wheel build).

---

## 9.1 Test & Evaluation Deliverables

| PRD item | Delivered as | Evidence |
|---|---|---|
| Versioned adversarial test-case library | [agent_redteam/attacks/core_suite.yaml](../agent_redteam/attacks/core_suite.yaml) — 13 cases, 6 categories, severity hints, tags, metadata | [tests/test_suite.py](../tests/test_suite.py) |
| Threat model and evaluation policy/rubric | [docs/ARCHITECTURE.md](ARCHITECTURE.md) (threat surface, design decisions) + declarative `Policy` rubric (must_refuse, must_not_contain, regex rules, tool allowlists) | [schemas.py](../agent_redteam/core/schemas.py) |
| Baseline evaluation dataset/run configuration | Built-in `core` suite + `mock:weak` / `mock:strong` targets as reproducible baselines | [mock_agent.py](../agent_redteam/adapters/mock_agent.py) |
| Evaluation run artifacts with results and evidence | `runs/<run_id>/{summary,results,records}.json` for every run | [runner.py](../agent_redteam/core/runner.py) |
| Category-level and run-level metrics report | Attack success rate, violation rate, pass rate, per-category breakdown | [runner.py](../agent_redteam/core/runner.py), [test_runner_compare.py](../tests/test_runner_compare.py) |
| Regression comparison report | `compare` command + `ComparisonReport` (regressions, improvements, still-violating, metric deltas) | [compare.py](../agent_redteam/core/compare.py) |

## 9.2 Framework / Engineering Deliverables

| PRD item | Delivered as |
|---|---|
| Python package with core execution & evaluation modules | `agent_redteam` installable package (pyproject.toml, `agent-redteam` console script) |
| Agent adapter interface + working adapter | `AgentAdapter` ABC; `mock:weak`, `mock:strong`, `HTTPAgentAdapter` |
| Configuration and schema validation | Pydantic v2 schemas with strict validation; YAML/JSON suite loader rejecting malformed cases with precise errors |
| Deterministic evaluator | `evaluators/deterministic.py` — keyword/regex/refusal/tool-allowlist checks with evidence capture |
| Configurable semantic evaluator | `evaluators/llm_judge.py` — OpenAI-compatible judge, temperature 0, structured JSON verdicts, explicit error handling |
| Severity and finding model | `Severity` (low→critical), `Finding` with reproduction steps, remediation guidance and evidence |
| Automated unit & integration tests | 86 pytest tests: schemas, suite, adapters, engine, evaluator, runner, compare, reports, API, LLM judge, dashboard |
| Dockerfile & reproducible setup | Non-root slim-image Dockerfile + `.dockerignore` + pinned deps in pyproject |

## 9.3 Backend / API Deliverables

| PRD item | Delivered as |
|---|---|
| Service for starting/monitoring runs | FastAPI app: `POST /runs` (202 + background execution) |
| Endpoint for run status & results | `GET /runs/{id}`, `GET /runs/{id}/results`, `GET /runs/{id}/report`, `GET /healthz` |
| Structured JSON result format | Pydantic-serialized `EvaluationResult` / `RunSummary` JSON |
| Batch evaluation support | Whole-suite execution in a single run (batch by design) |
| Error handling, timeouts, rate limits, logging | Engine-level per-case timeout + global rate limit; API rejects unauthorized targets synchronously (HTTP 400); invalid payloads → 422 |

## 9.4 Reporting / Interface Deliverables

| PRD item | Delivered as |
|---|---|
| Human-readable evaluation report | Markdown report with summary metrics, category table, findings, baseline diff |
| Finding list with severity and evidence | Findings section in Markdown + CSV export (`<run>-findings.csv`) |
| Category-level score summary | Per-category table in report + dashboard |
| Baseline/regression comparison | `--compare-to` flag in `report`; `compare` command |
| Optional dashboard for historical runs & trends | `dashboard` command → dependency-free HTML: stat cards, run history, ASR/pass-rate trend SVGs, category breakdown, findings browser |

## 9.5 Deployment / Documentation Deliverables

| PRD item | Delivered as |
|---|---|
| Dockerized framework/service | [Dockerfile](../Dockerfile) (`uvicorn agent_redteam.api.main:app`) |
| GitHub Actions workflow | [.github/workflows/ci.yml](../.github/workflows/ci.yml) — ruff + pytest (3.11/3.12/3.13) + wheel build; CI green on push |
| Optional CI evaluation quality gate | `run` exits 1 when violations exist — usable as a release gate |
| README with setup, suite format, usage | [README.md](../README.md) |
| Architecture diagram & HLD/LLD | [docs/ARCHITECTURE.md](ARCHITECTURE.md) (pipeline, components, data flow, design decisions) |
| Final demo & presentation | 3-command demo: `run` on `mock:weak` → `run` on `mock:strong` → `compare`; plus HTML dashboard |
| Limitations, safety boundaries, responsible use | [docs/RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) + README limitations section |

---

## Functional scope (PRD §2.1) — all 10 must-haves implemented

1. Configurable agent adapter (mock + HTTP) ✅
2. Versioned adversarial test-case library ✅
3. Single-turn and controlled multi-turn execution ✅
4. Deterministic + configurable LLM-as-judge evaluation ✅
5. Severity classification and evidence capture ✅
6. Run-level metrics (ASR, violation rate, pass rate, category scores) ✅
7. Baseline comparison for regressions ✅
8. CLI + REST API to start and retrieve evaluations ✅
9. JSON/CSV/Markdown exports + HTML dashboard ✅
10. Safe execution controls (timeouts, rate limits, isolation, secret handling) ✅

## Stretch goals delivered ahead of schedule

- ✅ **Dashboard for historical scores, trends, findings, regressions** (PRD §2.2-5)
- ✅ **CI/CD quality-gate support** via exit codes (PRD §2.2-6)
- ◻ Remaining stretch items tracked in [docs/ROADMAP.md](ROADMAP.md)

## v2.0.0: agents that think for themselves (mentor feedback)

Mentor feedback: the agents should not be hardcoded. Both were:

| Before (v1) | After (v2) | Where |
|---|---|---|
| Target agent = keyword `if/else` script (`mock:weak` always fails, `mock:strong` always passes) | `llm:weak` / `llm:strong`: a real model decides its replies and tool calls; profiles differ only by guardrails in the system prompt | [llm_agent.py](../agent_redteam/adapters/llm_agent.py) |
| Attacker picks the next category by a fixed rule | LLM planner reads the history and the target's replies, picks category + strategy or stops; validated, with the rule as fallback | [planner.py](../agent_redteam/core/planner.py), [adaptive.py](../agent_redteam/core/adaptive.py) |
| Grading checked the mock's own fake password | Fresh canary secrets planted per run; every case checks for them | [core_suite.yaml](../agent_redteam/attacks/core_suite.yaml) |

Measured on a local `qwen2.5:3b` (3 repeats; raw data in
[results/llm_experiment_20261107.json](results/llm_experiment_20261107.json)):

| Target | Fixed suite attack success rate | Adaptive loop violations |
|---|---|---|
| `llm:weak` | 79% (77–83%) | 6 / 9 |
| `llm:strong` | 31% (31–31%) | 1 / 9 |

Guardrails reduced the attack success rate from 79% to 31%. The strong agent leaked no
canary but was jailbroken by a "developer mode" prompt in all 3 runs, and an AI-generated attack
(asking for the password "in a format") made it search for the secret instead of refusing.
Limitations, including keyword-grading misjudgements found by manual review and the
weakness of a 3B attacker, are listed in the README.

Safety of the new parts: tools are simulated (never executed); model endpoints use the
same authorization as HTTP targets; planner output is strictly validated with budgets it
cannot raise; tests are offline and hermetic (196 passing, plus 1 opt-in live test).

## Safety summary

- Safe by default: external targets refused without explicit consent + host allowlist (CLI and API).
- Adapters never execute agent tool calls; violations are detected from captured traces.
- All artifacts local; `runs/` and `.env` git-ignored; no secrets in the repo.
- Attack strings in the suite and mock agents are fictional test data.

## Signature readiness

The implementation, tests, documentation and evaluation artifacts required by the PRD are
complete and verified. Ready for mentor review and final demonstration.
