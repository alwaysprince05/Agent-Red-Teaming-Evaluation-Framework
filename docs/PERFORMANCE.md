# Performance & Reliability Report (PRD §3.3)

All numbers measured on the project author's machine (Apple Silicon, Python 3.14 venv)
with the built-in 13-case `core` suite and deterministic mock targets, `rate_limit_s=0`,
3 iterations per configuration (39 case executions per row). Reproduce with:

```bash
agent-redteam benchmark --target mock:weak   --iterations 3 --json
agent-redteam benchmark --target mock:strong --iterations 3 --json
agent-redteam run --suite core --target mock:weak   # then: report --run <id>
```

## Throughput & latency (engine + adapter + capture)

| Configuration | Case executions | Wall time | Throughput | Avg latency | p95 latency | Timeout rate | Error rate |
|---|---|---|---|---|---|---|---|
| `mock:weak` | 39 | 0.002 s | **18,250 cases/s** | 0.004 ms | 0.005 ms | 0% | 0% |
| `mock:strong` | 39 | 0.002 s | **18,413 cases/s** | 0.003 ms | 0.005 ms | 0% | 0% |

- Tool-call trace capture verified during benchmarking (weak target: 9 tool calls observed,
  strong target: 0 — matching the expected hardened behavior).

## Report & artifact performance

| Operation | Measured |
|---|---|
| Markdown + CSV report generation (13 findings) | **0.001 s** |
| Run artifact size (`summary` + `results` + `records` JSON, 13-case run) | **~26 KB** |

## Interpretation & real-world expectations

- Mock targets are in-process and deterministic, so these numbers measure the **framework
  overhead**: parsing, orchestration, evaluation, evidence capture and serialization — not
  model latency.
- With a real HTTP agent, per-case time will be dominated by target latency (hundreds of ms
  to seconds). The engine adds only sub-millisecond overhead per case; the per-case timeout
  (default 15 s) and rate limit are the operative bounds in that regime.
- Scaling example: a 100-case suite against a real agent at ~1 s/case ≈ 100 s sequential,
  bounded by the configured rate limit; failure isolation ensures one timeout/error never
  blocks the remaining cases.

## Reliability checks covered by tests

- Timeout path (`ExecStatus.timeout`) reported as evaluation `error`, never a silent pass —
  [tests/test_engine_evaluator.py](../tests/test_engine_evaluator.py)
- Transport-failure path (`AgentResponse.error`) isolated per case and excluded from ASR math
- Repeated benchmark iterations produce consistent counts (deterministic mock behavior)
- Evaluator stability: deterministic evaluator is pure and repeatable across runs; the
  optional LLM judge is temperature 0, and any judge failure is surfaced as an explicit
  `error` result rather than a pass (PRD §4.3-5 variance tracking happens via repeat runs)

## Follow-ups for real deployments

1. Measure token/API cost per run once a real (authorized) model target is configured.
2. Add p50/p99 latency columns to the dashboard trend view if needed.
3. Track evaluator disagreement (deterministic vs judge) across repeat runs in CI.
