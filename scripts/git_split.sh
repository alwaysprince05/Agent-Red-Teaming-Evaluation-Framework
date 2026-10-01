#!/usr/bin/env bash
# Incremental-history helper: commits the project in logical feature steps.
#
# Usage:
#   scripts/git_split.sh "Author Name" "author@example.com"
#   PUSH=1 scripts/git_split.sh "Author Name" "author@example.com"   # also push to origin
#
# Identity comes from the two arguments (recommended: your GitHub username and
# your GitHub noreply email, e.g. "alwaysprince05" "alwaysprince05@users.noreply.github.com").
# Commits are created sequentially with the current clock - no fake dates.
set -euo pipefail

if [ $# -ge 2 ]; then
  export GIT_AUTHOR_NAME="$1"
  export GIT_AUTHOR_EMAIL="$2"
  export GIT_COMMITTER_NAME="$1"
  export GIT_COMMITTER_EMAIL="$2"
fi

PUSH="${PUSH:-0}"
REMOTE="${REMOTE:-https://github.com/alwaysprince05/Agent-Red-Teaming-Evaluation-Framework.git}"

commit_step() {
  local msg="$1"
  shift
  if [ -z "$(git status --porcelain "$@")" ]; then
    echo "SKIP (nothing to commit): $msg"
    return
  fi
  git add -- "$@"
  git commit -m "$msg"
  echo "OK: $msg"
}

# 1. Project scaffolding
commit_step "chore: add .gitignore, .dockerignore and .env.example" .gitignore .dockerignore .env.example
commit_step "chore: add packaging metadata and tool config (pyproject.toml)" pyproject.toml
commit_step "chore: add MIT license" LICENSE

# 2. Core schemas
commit_step "feat(core): policy, test case, execution record and evaluation schemas" \
  agent_redteam/core/schemas.py
commit_step "chore(core): package init with schema re-exports" agent_redteam/core/__init__.py

# 3. Suite loading
commit_step "feat(core): YAML/JSON suite loader with strict validation" agent_redteam/core/suite.py

# 4. Adapters
commit_step "feat(adapters): adapter interface and safe-by-default target authorization" \
  agent_redteam/adapters/base.py
commit_step "feat(adapters): deterministic weak/strong mock agents" \
  agent_redteam/adapters/mock_agent.py
commit_step "feat(adapters): HTTP adapter with timeout handling" \
  agent_redteam/adapters/http_agent.py
commit_step "chore(adapters): package exports" agent_redteam/adapters/__init__.py

# 5. Attack library
commit_step "feat(attacks): core adversarial suite (13 cases, 6 categories)" \
  agent_redteam/attacks/core_suite.yaml

# 6. Evaluators
commit_step "feat(evaluators): deterministic policy evaluator with evidence capture" \
  agent_redteam/evaluators/deterministic.py
commit_step "feat(evaluators): optional LLM-as-judge with structured verdicts" \
  agent_redteam/evaluators/llm_judge.py
commit_step "chore(evaluators): package exports" agent_redteam/evaluators/__init__.py

# 7. Engine and runner
commit_step "feat(engine): execution engine with timeout, rate limit and isolation" \
  agent_redteam/core/engine.py
commit_step "feat(runner): full pipeline orchestration with metrics and findings" \
  agent_redteam/core/runner.py

# 8. Comparison and reports
commit_step "feat(compare): baseline comparison with regressions and metric deltas" \
  agent_redteam/core/compare.py
commit_step "feat(reports): Markdown report and CSV findings export" \
  agent_redteam/reports/generate.py
commit_step "chore(reports): package marker" agent_redteam/reports/__init__.py

# 9. CLI and API
commit_step "feat(cli): run, compare, report and list-attacks commands" agent_redteam/cli.py
commit_step "feat(api): FastAPI service for starting and monitoring runs" agent_redteam/api/main.py
commit_step "chore(api): package marker" agent_redteam/api/__init__.py

# 10. Package root
commit_step "chore: package init and py.typed marker" agent_redteam/__init__.py agent_redteam/py.typed

# 11. Tests
commit_step "test: shared fixtures for suite and mock agents" tests/conftest.py
commit_step "test: schema validation coverage" tests/test_schemas.py
commit_step "test: suite loading and malformed-input rejection" tests/test_suite.py
commit_step "test: adapter safety and mock agent behavior" tests/test_adapters.py
commit_step "test: engine and deterministic evaluator coverage" tests/test_engine_evaluator.py
commit_step "test: runner pipeline and baseline comparison" tests/test_runner_compare.py
commit_step "test: report generation" tests/test_reports.py
commit_step "test: API lifecycle and safety rejections" tests/test_api.py
commit_step "test: LLM judge parsing, config and failure handling" tests/test_llm_judge.py

# 12. CI and container
commit_step "ci: GitHub Actions workflow (lint, tests, build)" .github/workflows/ci.yml
commit_step "build: Dockerfile for the API service" Dockerfile

# 13. Docs and examples
commit_step "docs: README with quickstart, suite format and API guide" README.md
commit_step "docs: architecture, responsible use and roadmap" docs
commit_step "docs: example custom suite" attacks_example
commit_step "chore: incremental-history helper script" scripts

echo
echo "Commits created: $(git rev-list --count HEAD)"

if [ "$PUSH" = "1" ]; then
  if ! git remote get-url origin >/dev/null 2>&1; then
    git remote add origin "$REMOTE"
  fi
  git push -u origin main
fi
