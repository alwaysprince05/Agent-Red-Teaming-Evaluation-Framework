# Responsible Use, Limitations & Safety Boundaries

## Authorization rule (non-negotiable)

Only run this framework against agents **you own** or have **written permission** to test.
Testing third-party or public AI services without authorization may be illegal, violates
their terms of service, and is outside the intended use of this project.

## How the framework enforces safe defaults

1. **Built-in targets are simulated.** `mock:weak` and `mock:strong` are scripted agents
   inside the framework. The full pipeline — attacks, evaluation, metrics, reports — can be
   exercised without ever touching a real system.
2. **External targets are refused by default.** `resolve_target` rejects every non-loopback
   HTTP target unless the caller passes `allow_external=True` *and* the host appears in an
   explicit allowlist. The API enforces this synchronously (HTTP 400) before starting a run.
3. **No tool execution.** Adapters only *send conversation turns* and capture responses.
   The framework never executes an agent's tool calls; `tool_allowlist` violations are
   evaluated from the trace, not performed.
4. **Execution limits.** Per-case timeout, global rate limit and max-turn cap are enforced
   by the engine and configurable per run.
5. **Local-only artifacts.** Runs, evidence and reports are written to local directories
   (`runs/`, `reports/out/`), which are git-ignored. Nothing is uploaded anywhere.
6. **Secrets hygiene.** `.env` is git-ignored; the committed `.env.example` contains only
   empty placeholders. No real credentials are needed — and none are embedded in the
   attack library (all leaked strings in the mock targets and suite are fictional).

## What the framework does *not* do

- It does not exploit, persist, or pivot: a "successful attack" is a recorded policy
  violation in a captured response, nothing more.
- It does not bypass authentication, rate limits, or monitoring of any target.
- It does not generate adaptive/mutating attacks automatically (future work; each case is
  a fixed, reviewed, version-controlled script).

## Evidence handling

Evidence (response text, matched rules, tool-call traces) may contain sensitive data from
*your own* target. Keep `runs/` local, do not commit it, and sanitize before sharing a
report externally.

## Disclosure

If an authorized evaluation uncovers a real vulnerability in someone else's system (with
permission to test), follow coordinated disclosure: report privately to the owner, agree
on a fix timeline, and publish details only after remediation.
