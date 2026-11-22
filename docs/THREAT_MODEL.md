# Threat Model

This covers the framework's own attack surface: the REST API and web UI
(`agent_redteam/api/main.py`, `agent_redteam/web/`) and the adapters that reach
target agents. It is organised by STRIDE. It does not cover the security of the
agents being tested; finding their weaknesses is the framework's job.

## Assets

- The host running the service: its files, its network position, its CPU time.
- Run artifacts under `runs/` and reports under `reports/out/`.
- API keys for an LLM endpoint, if the operator configured one (environment only).
- Third parties that a careless or malicious user might try to point the scanner at.

## Trust boundaries

| Boundary | Untrusted side |
|---|---|
| Browser → API | Every request body and query parameter |
| API → target agent | Every reply and tool-call payload from the agent |
| Operator → configuration | Trusted (environment variables, CLI flags) |

Two deployment postures share one code path: **local** (default, binds to
127.0.0.1) and **public demo** (`AGENT_REDTEAM_PUBLIC_MODE=1`).

## STRIDE

| Threat | Example | Mitigation | Where |
|---|---|---|---|
| **Spoofing** | A user claims permission to scan a host they do not own | URL targets need `authorized=true`; non-loopback hosts also need `allow_external_targets` and an explicit host allowlist. In public mode URL targets are refused outright. | `start_run`, `validate_external_target` |
| **Spoofing** | Scanning a government or military chatbot | Hard guardrail refuses `.gov`, `.mil`, `.edu`, `.int` and country forms such as `gov.in`, `ac.in`, `nic.in`. No flag disables it. | `is_protected_host` |
| **Tampering** | Path traversal through `run_id` (`..%2F..%2Fetc`) | Run ids must match `YYYYMMDD-HHMMSS-<8 hex>` before any file is read | `_check_run_id` |
| **Tampering** | Reading or writing arbitrary files via `suite` or `output_dir` | Public mode forces the built-in suite and `runs/`; the `output_dir` query parameter is ignored there | `start_run`, `_run_output_dir` |
| **Repudiation** | "That report is not what you ran" | Each summary records the framework version and the SHA-256 of the suite file; finding ids are a hash of target and case id | `RunSummary`, `stable_finding_id` |
| **Information disclosure** | Real secrets leaking through a test | Agents only hold fake values (`CANARY-…`, dummy keys). The demo bots are scripted; the LLM agents default to a local Ollama model, so transcripts stay on the machine. | `adapters/` |
| **Information disclosure** | XSS from a malicious agent reply rendered in the UI | Every dynamic value is HTML-escaped before insertion; highlighting works on the escaped text | `esc()`, `highlight()` in `app.js` |
| **Denial of service** | Flooding scans or playground calls on the public demo | At most 3 concurrent scans and 60 playground messages per minute in public mode; request timeouts are capped at 120 s; at most 200 runs kept in memory | `start_run`, `_playground_rate_limit`, `_prune_runs` |
| **Elevation of privilege** | Container breakout from the service | The Docker image runs as a non-root user and installs only the package and the published results | `Dockerfile` |

## Known gaps

- No authentication: the public demo is meant to be anonymous and stateless.
  Anything that needs accounts (saved projects, private targets) is out of scope.
- Rate limits are global, not per client, because client IPs behind a hosting
  proxy can be forged.
- In-memory run state is lost on restart; finished artifacts remain on disk.
- The refusal check is keyword based and can misjudge some phrasings; leaks are
  still caught by canary and content rules.
