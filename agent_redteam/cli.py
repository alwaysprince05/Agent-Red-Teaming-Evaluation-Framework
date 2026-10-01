"""Command-line interface for the Agent Red-Teaming & Evaluation Framework."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_redteam import __version__
from agent_redteam.adapters.base import MOCK_TARGETS, TargetNotAuthorizedError, resolve_target
from agent_redteam.core.compare import compare_run_dirs, load_results_for_run
from agent_redteam.core.runner import RunOptions, execute_run
from agent_redteam.core.suite import SuiteError
from agent_redteam.reports.dashboard import generate_dashboard
from agent_redteam.reports.generate import generate_findings_csv, generate_markdown_report

BUILTIN_SUITES = {
    "core": str(Path(__file__).parent / "attacks" / "core_suite.yaml"),
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-redteam",
        description="Red-team and safety-evaluation framework for AI agents. "
        "Only test agents you own or are authorized to test.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run an adversarial suite against a target agent")
    run.add_argument("--suite", default="core", help="Built-in suite name or path to a suite YAML/JSON")
    run.add_argument("--target", default="mock:weak", help="mock:weak | mock:strong | authorized http(s) URL")
    run.add_argument(
        "--allow-external", action="store_true",
        help="Explicitly authorize testing an external (non-loopback) HTTP target",
    )
    run.add_argument(
        "--allowed-hosts", default="",
        help="Comma-separated host allowlist required for non-loopback external targets",
    )
    run.add_argument("--timeout", type=float, default=15.0, help="Per-case timeout in seconds")
    run.add_argument("--rate-limit", type=float, default=0.2, help="Seconds between sends")
    run.add_argument(
        "--use-llm-judge", action="store_true",
        help="Also use the configured LLM-as-judge (falls back to deterministic on error)",
    )
    run.add_argument("--out", default="runs", help="Directory for run artifacts")

    cmp = sub.add_parser("compare", help="Compare two runs (baseline vs current)")
    cmp.add_argument("--baseline", required=True, help="Baseline run ID")
    cmp.add_argument("--current", required=True, help="Current run ID")
    cmp.add_argument("--runs-dir", default="runs", help="Directory containing run artifacts")

    rep = sub.add_parser("report", help="Generate Markdown + CSV reports for a run")
    rep.add_argument("--run", required=True, help="Run ID")
    rep.add_argument("--runs-dir", default="runs", help="Directory containing run artifacts")
    rep.add_argument("--compare-to", default=None, help="Baseline run ID to diff against")
    rep.add_argument("--out", default="reports/out", help="Output directory for reports")

    dash = sub.add_parser("dashboard", help="Generate an HTML dashboard from all runs")
    dash.add_argument("--runs-dir", default="runs", help="Directory containing run artifacts")
    dash.add_argument("--out", default="reports/out/dashboard.html", help="Output HTML path")

    sub.add_parser("list-attacks", help="List built-in adversarial suites")
    return p


def _suite_path(name_or_path: str) -> str:
    if name_or_path in BUILTIN_SUITES:
        return BUILTIN_SUITES[name_or_path]
    return name_or_path


def _print_summary_line(summary) -> None:
    m = summary.metrics
    print(f"\nRun {summary.run_id} complete.")
    print(f"  target={summary.target}  suite={summary.suite}")
    print(
        f"  cases={m.total_cases} executed={m.executed} violations={m.violations} errors={m.errors}"
    )
    print(
        f"  attack_success_rate={m.attack_success_rate:.2%}  "
        f"violation_rate={m.violation_rate:.2%}  pass_rate={m.pass_rate:.2%}"
    )
    if summary.findings:
        print(f"  findings: {len(summary.findings)}")
        for f in summary.findings:
            print(f"    - [{f.severity.value.upper():8s}] {f.test_id} ({f.category})")
    else:
        print("  findings: none")


def cmd_run(args: argparse.Namespace) -> int:
    try:
        adapter = resolve_target(
            args.target,
            allow_external=args.allow_external,
            host_allowlist=[h.strip() for h in args.allowed_hosts.split(",") if h.strip()] or None,
        )
    except (TargetNotAuthorizedError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        run_id, summary, _results, _records = execute_run(
            _suite_path(args.suite),
            adapter,
            RunOptions(
                use_llm_judge=args.use_llm_judge,
                rate_limit_s=args.rate_limit,
                timeout_s=args.timeout,
                output_dir=Path(args.out),
            ),
        )
    except SuiteError as exc:
        print(f"ERROR: invalid suite: {exc}", file=sys.stderr)
        return 2

    _print_summary_line(summary)
    print(f"\nArtifacts: {Path(args.out) / run_id}")
    # Exit code 1 signals violations were found (useful as a CI quality gate).
    return 1 if summary.metrics.violations else 0


def cmd_compare(args: argparse.Namespace) -> int:
    runs_dir = Path(args.runs_dir)
    try:
        base = load_results_for_run(runs_dir, args.baseline)
        cur = load_results_for_run(runs_dir, args.current)
        report = compare_run_dirs(runs_dir, args.baseline, args.current)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not base or not cur:
        print("ERROR: one of the runs has no results", file=sys.stderr)
        return 2

    print(f"Baseline {args.baseline} -> Current {args.current}")
    if report.metric_deltas:
        for k, v in report.metric_deltas.items():
            print(f"  {k}: {v:+.2%}")
    print(f"  regressions : {len(report.regressions)}")
    for r in report.regressions:
        print(f"    - {r.test_id} ({r.category}): {r.detail}")
    print(f"  improvements: {len(report.improvements)}")
    for r in report.improvements:
        print(f"    - {r.test_id} ({r.category}): {r.detail}")
    if report.unchanged_violations:
        print(f"  still violating: {len(report.unchanged_violations)}")
        for r in report.unchanged_violations:
            print(f"    - {r.test_id} ({r.category}): {r.detail}")

    out = runs_dir / f"comparison-{args.baseline}-vs-{args.current}.json"
    out.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")
    print(f"\nComparison saved: {out}")
    return 1 if report.regressions else 0


def cmd_report(args: argparse.Namespace) -> int:
    runs_dir = Path(args.runs_dir)
    summary_path = runs_dir / args.run / "summary.json"
    if not summary_path.exists():
        print(f"ERROR: run not found: {summary_path}", file=sys.stderr)
        return 2
    from agent_redteam.core.schemas import RunSummary

    summary = RunSummary.model_validate_json(summary_path.read_text(encoding="utf-8"))
    results = load_results_for_run(runs_dir, args.run)

    comparison = None
    if args.compare_to:
        try:
            comparison = compare_run_dirs(runs_dir, args.compare_to, args.run)
        except Exception as exc:
            print(f"ERROR: comparison failed: {exc}", file=sys.stderr)
            return 2

    md_path = generate_markdown_report(
        summary, results, Path(args.out) / f"{args.run}.md", comparison=comparison
    )
    csv_path = generate_findings_csv(summary, Path(args.out) / f"{args.run}-findings.csv")
    print(f"Markdown report: {md_path}")
    print(f"CSV findings:    {csv_path}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    out = generate_dashboard(args.runs_dir, args.out)
    runs = len(list(Path(args.runs_dir).glob("*/summary.json")))
    print(f"Dashboard ({runs} run(s)): {out}")
    return 0


def cmd_list_attacks(_args: argparse.Namespace) -> int:
    print("Built-in suites:")
    for name, path in BUILTIN_SUITES.items():
        print(f"  {name}: {path}")
    print("Safe demo targets:", ", ".join(MOCK_TARGETS))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {
        "run": cmd_run,
        "compare": cmd_compare,
        "report": cmd_report,
        "dashboard": cmd_dashboard,
        "list-attacks": cmd_list_attacks,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
