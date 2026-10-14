# Demo Evidence — Verified Run Log

All commands below were executed on 2026-10-14, offline, against the built-in
deterministic mock agents (`mock:weak` / `mock:strong`). Run artifacts live
under `runs/<run_id>/` on this machine (gitignored; evidence stays local).

## 1. Baseline evaluation — vulnerable agent

```
agent-redteam run --suite core --target mock:weak
```

- Run ID `20261014-161722-b3d0bbe8` · 13 cases, 13 violations, 0 errors
- attack_success_rate 100% · pass_rate 0% · exit code 1 (CI gate fired correctly)
- Findings span all 6 categories: prompt_injection, jailbreak, data_leakage,
  unsafe_tool_use, multi_turn_manipulation, indirect_injection
  (severities: 6 critical, 6 high, 1 medium)

## 2. Evaluation — hardened agent

```
agent-redteam run --suite core --target mock:strong
```

- Run ID `20261014-161806-9dc69452` · 13 cases, 0 violations
- attack_success_rate 0% · pass_rate 100% · exit code 0

## 3. Regression comparison

```
agent-redteam compare --baseline 20261014-161722-b3d0bbe8 --current 20261014-161806-9dc69452
```

- Result: **0 regressions, 13 improvements**
- ASR −100.00%, violation_rate −100.00%, pass_rate +100.00%
- Comparison artifact: `runs/comparison-20261014-161722-b3d0bbe8-vs-20261014-161806-9dc69452.json`

## 4. Reports

```
agent-redteam report --run 20261014-161722-b3d0bbe8 --compare-to 20261014-161806-9dc69452
agent-redteam dashboard && open reports/out/dashboard.html
```

- Markdown: `reports/out/20261014-161722-b3d0bbe8.md`
- CSV findings: `reports/out/20261014-161722-b3d0bbe8-findings.csv`
- Dashboard: `reports/out/dashboard.html` (4 runs, trend charts, findings browser)

## 5. Adaptive closed-loop agent

```
agent-redteam adaptive --target mock:weak --max-rounds 3 --cases-per-round 5
```

- 3 rounds, each plan → generate → attack → reflect (trace shown live)
- Generated 15 cases via deterministic mutation, all validated and executed
- 15/15 violations found; every generated attack hit the vulnerable target
- Round suites persisted under `runs/adaptive_suites/round0{1,2,3}_prompt_injection.yaml`

## Interpretation

The same 13-case suite cleanly separates a deliberately vulnerable agent from
a hardened one, violations carry captured evidence with remediation guidance,
and the adaptive loop broadens coverage on its own while staying inside hard
budgets (≤50 cases/request, ≤20 rounds). This demonstrates the framework's
core claim: reproducible, evidence-backed adversarial testing with a CI gate.
