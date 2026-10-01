"""FastAPI service for starting and monitoring evaluation runs.

Safe by default: external HTTP targets require allow_external_targets=true and,
for non-loopback hosts, an entry in allowed_hosts.
"""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent_redteam.adapters.base import MOCK_TARGETS, TargetNotAuthorizedError, resolve_target
from agent_redteam.core.runner import RunOptions, execute_run
from agent_redteam.core.suite import SuiteError
from agent_redteam.reports.generate import generate_findings_csv, generate_markdown_report

app = FastAPI(
    title="Agent Red-Teaming & Evaluation Framework",
    version="0.1.0",
    description="Reproducible adversarial testing for AI agents. "
    "Only test agents you own or are authorized to test.",
)

# In-memory run registry (artifacts remain the durable store under runs/).
_RUNS: dict[str, dict] = {}
_LOCK = threading.Lock()
BUILTIN_SUITE_PATH = Path(__file__).parent.parent / "attacks" / "core_suite.yaml"


class RunRequest(BaseModel):
    suite: str = Field(default="core", description="Built-in 'core' or path to suite YAML/JSON")
    target: str = Field(
        default="mock:weak",
        description="mock:weak | mock:strong | authorized http(s) URL",
    )
    allow_external_targets: bool = False
    allowed_hosts: list[str] = Field(default_factory=list)
    timeout_s: float = Field(default=15.0, gt=0, le=120)
    rate_limit_s: float = Field(default=0.2, ge=0, le=30)
    use_llm_judge: bool = False
    output_dir: str = "runs"


class RunCreated(BaseModel):
    run_id: str
    status: str
    poll_url: str


def _suite_path(name_or_path: str) -> Path:
    if name_or_path in ("core", "default"):
        return BUILTIN_SUITE_PATH
    return Path(name_or_path)


def _execute_background(run_id: str, suite_path: Path, req: RunRequest) -> None:
    try:
        adapter = resolve_target(
            req.target,
            allow_external=req.allow_external_targets,
            host_allowlist=req.allowed_hosts or None,
        )
        _rid, summary, results, _records = execute_run(
            suite_path,
            adapter,
            RunOptions(
                use_llm_judge=req.use_llm_judge,
                rate_limit_s=req.rate_limit_s,
                timeout_s=req.timeout_s,
                output_dir=Path(req.output_dir),
            ),
            run_id=run_id,
        )
        with _LOCK:
            _RUNS[run_id].update(
                status="completed",
                finished_at=time.time(),
                metrics=summary.metrics.model_dump(),
                findings_count=len(summary.findings),
            )
    except (TargetNotAuthorizedError, SuiteError, ValueError) as exc:
        with _LOCK:
            _RUNS[run_id].update(status="failed", error=str(exc), finished_at=time.time())
    except Exception as exc:  # unexpected
        with _LOCK:
            _RUNS[run_id].update(
                status="failed", error=f"internal error: {exc}", finished_at=time.time()
            )


@app.post("/runs", response_model=RunCreated, status_code=202)
def start_run(req: RunRequest) -> RunCreated:
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    # Validate the target *synchronously* so unauthorized external targets are
    # rejected with 400 before any run is registered.
    try:
        suite_path = _suite_path(req.suite)
        if not suite_path.exists():
            raise SuiteError(f"suite not found: {suite_path}")
        resolve_target(
            req.target,
            allow_external=req.allow_external_targets,
            host_allowlist=req.allowed_hosts or None,
        )
    except (TargetNotAuthorizedError, SuiteError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    with _LOCK:
        _RUNS[run_id] = {
            "status": "running",
            "started_at": time.time(),
            "target": req.target,
            "output_dir": req.output_dir,
        }
    threading.Thread(
        target=_execute_background, args=(run_id, suite_path, req), daemon=True
    ).start()
    return RunCreated(run_id=run_id, status="running", poll_url=f"/runs/{run_id}")


@app.get("/runs/{run_id}")
def run_status(run_id: str) -> dict:
    with _LOCK:
        entry = _RUNS.get(run_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"unknown run {run_id}")
        return dict(entry)


def _run_output_dir(run_id: str, output_dir: str | None) -> str:
    if output_dir:
        return output_dir
    with _LOCK:
        entry = _RUNS.get(run_id)
        if entry and entry.get("output_dir"):
            return str(entry["output_dir"])
    return "runs"


@app.get("/runs/{run_id}/results")
def run_results(run_id: str, output_dir: str | None = None) -> dict:
    base = Path(_run_output_dir(run_id, output_dir))
    results_path = base / run_id / "results.json"
    if not results_path.exists():
        raise HTTPException(status_code=404, detail=f"no results for run {run_id}")
    results = [
        line
        for line in results_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    summary_path = base / run_id / "summary.json"
    summary = summary_path.read_text(encoding="utf-8") if summary_path.exists() else None
    return {"run_id": run_id, "summary": summary, "results": results}


@app.get("/runs/{run_id}/report")
def run_report(run_id: str, output_dir: str | None = None) -> dict:
    from agent_redteam.core.schemas import RunSummary

    base = Path(_run_output_dir(run_id, output_dir))
    summary_path = base / run_id / "summary.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail=f"no summary for run {run_id}")
    summary = RunSummary.model_validate_json(summary_path.read_text(encoding="utf-8"))
    md = generate_markdown_report(summary, [], Path("reports/out") / f"{run_id}.md")
    csv_path = generate_findings_csv(summary, Path("reports/out") / f"{run_id}-findings.csv")
    return {
        "run_id": run_id,
        "markdown_report": str(md),
        "findings_csv": str(csv_path),
        "metrics": summary.metrics.model_dump(),
    }


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "safe_targets": list(MOCK_TARGETS)}
