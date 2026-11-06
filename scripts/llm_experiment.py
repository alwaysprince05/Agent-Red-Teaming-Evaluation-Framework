"""Run the real-LLM experiment: fixed suite vs adaptive agent, weak vs strong guardrails.

Real models vary between runs even at temperature 0, so the fixed suite is repeated
and reported as mean (min-max) attack success rate, not a single number.

Usage (after `ollama pull qwen2.5:3b`; see README "Testing a real LLM agent"):
    python scripts/llm_experiment.py --repeats 3 --rounds 3
Writes runs/experiments/<timestamp>.json and prints a Markdown table for the report.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import statistics
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_redteam.adapters.base import resolve_target  # noqa: E402
from agent_redteam.adapters.llm_agent import LLMTargetConfig  # noqa: E402
from agent_redteam.cli import BUILTIN_SUITES  # noqa: E402
from agent_redteam.core.adaptive import AdaptiveLimit, run_adaptive  # noqa: E402
from agent_redteam.core.runner import RunOptions, execute_run  # noqa: E402


def check_endpoint(cfg: LLMTargetConfig) -> None:
    try:
        httpx.get(f"{cfg.base_url}/models", timeout=5).raise_for_status()
    except httpx.HTTPError as exc:
        sys.exit(f"Model endpoint {cfg.base_url} is not reachable ({exc}). Is Ollama running?")


def fmt(values: list[float]) -> str:
    return f"{statistics.mean(values):.0%} ({min(values):.0%}-{max(values):.0%})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repeats", type=int, default=3, help="Fixed-suite repetitions per target (1-10)")
    ap.add_argument("--rounds", type=int, default=3, help="Adaptive rounds per target (cap 20)")
    ap.add_argument("--cases-per-round", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=120.0, help="Per-case timeout seconds")
    ap.add_argument("--out", default="runs", help="Artifact directory")
    args = ap.parse_args()
    repeats = max(1, min(args.repeats, 10))

    cfg = LLMTargetConfig.from_env()
    check_endpoint(cfg)
    out = Path(args.out)
    opts = RunOptions(rate_limit_s=0.0, timeout_s=args.timeout, output_dir=out)
    results: dict = {"model": cfg.model, "base_url": cfg.base_url, "repeats": repeats, "targets": {}}

    for spec in ("llm:weak", "llm:strong"):
        asr, errors, run_ids = [], [], []
        for i in range(repeats):
            # Fresh agent per repeat: new canaries, no shared state.
            _rid, summary, _r, _rec = execute_run(BUILTIN_SUITES["core"], resolve_target(spec), opts)
            asr.append(summary.metrics.attack_success_rate)
            errors.append(summary.metrics.errors)
            run_ids.append(summary.run_id)
            print(f"{spec} fixed run {i + 1}/{repeats}: ASR={asr[-1]:.0%} errors={errors[-1]}", flush=True)
        report = run_adaptive(
            resolve_target(spec),
            BUILTIN_SUITES["core"],
            limits=AdaptiveLimit(max_rounds=args.rounds, cases_per_round=args.cases_per_round),
            run_options=opts,
            output_dir=out,
        )
        adaptive_rate = report.total_violations / report.total_executed if report.total_executed else 0.0
        found = f"{report.total_violations}/{report.total_executed}"
        print(f"{spec} adaptive ({report.planner} planner): {found} violations")
        results["targets"][spec] = {
            "fixed_asr": asr,
            "fixed_errors": errors,
            "fixed_run_ids": run_ids,
            "adaptive": dataclasses.asdict(report),
            "adaptive_violation_rate": adaptive_rate,
        }

    path = out / "experiments" / f"{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")

    print(f"\nModel: {cfg.model}   repeats: {repeats}   saved: {path}\n")
    print("| Target | Fixed suite ASR, mean (min-max) | Adaptive violations | Planner | Errors |")
    print("|---|---|---|---|---|")
    for spec, r in results["targets"].items():
        a = r["adaptive"]
        print(
            f"| `{spec}` | {fmt(r['fixed_asr'])} | {a['total_violations']}/{a['total_executed']} "
            f"| {a['planner']} | {sum(r['fixed_errors'])} |"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
