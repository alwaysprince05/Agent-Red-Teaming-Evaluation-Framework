"""HTML dashboard: run history, category trends and findings from runs/ artifacts.

Reads existing run directories (runs/<run_id>/summary.json) and renders a
self-contained, dependency-free HTML page. Read-only: it never modifies runs.
"""

from __future__ import annotations

import html
import time
from pathlib import Path

from agent_redteam.core.schemas import RunSummary

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       background: #0d1117; color: #e6edf3; margin: 0; padding: 2rem; }
h1 { font-size: 1.5rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
.muted { color: #8b949e; }
.cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 1rem 1.25rem; min-width: 150px; }
.card .num { font-size: 1.7rem; font-weight: 700; }
.card .lbl { color: #8b949e; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .92rem; }
th, td { border: 1px solid #30363d; padding: .45rem .6rem; text-align: left; }
th { background: #161b22; }
.badge { display: inline-block; border-radius: 999px; padding: .1rem .6rem;
         font-size: .75rem; font-weight: 600; }
.b-critical { background: #490202; color: #f85149; }
.b-high { background: #3a1d02; color: #f0883e; }
.b-medium { background: #33400a; color: #d4a72c; }
.b-low { background: #0f2f1f; color: #3fb950; }
.b-pass { background: #0f2f1f; color: #3fb950; }
.bar { background: #21262d; border-radius: 4px; height: 10px; overflow: hidden; }
.bar > div { height: 100%; background: #f85149; }
.bar > div.ok { background: #3fb950; }
footer { margin-top: 3rem; color: #8b949e; font-size: .8rem; }
"""


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _esc(s: str) -> str:
    return html.escape(str(s))


def discover_runs(runs_dir: str | Path) -> list[RunSummary]:
    """Load every valid run summary under runs_dir, oldest first."""
    base = Path(runs_dir)
    runs: list[tuple[float, RunSummary]] = []
    if not base.exists():
        return []
    for run_dir in sorted(base.iterdir()):
        summary_path = run_dir / "summary.json"
        if not run_dir.is_dir() or not summary_path.exists():
            continue
        try:
            summary = RunSummary.model_validate_json(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue  # skip unreadable/corrupt artifacts rather than failing the page
        runs.append((summary.created_at, summary))
    runs.sort(key=lambda t: t[0])
    return [s for _, s in runs]


def _trend_svg(runs: list[RunSummary], key: str, color: str, w: int = 560, h: int = 120) -> str:
    """Tiny inline SVG line chart for a 0..1 metric across runs."""
    if len(runs) < 2:
        return "<p class='muted'>Not enough runs for a trend yet (need 2+).</p>"
    vals = [getattr(r.metrics, key) for r in runs]
    step = (w - 20) / (len(vals) - 1)
    pts = [f"{10 + i * step:.1f},{h - 10 - v * (h - 20):.1f}" for i, v in enumerate(vals)]
    dots = "".join(
        f"<circle cx='{10 + i * step:.1f}' cy='{h - 10 - v * (h - 20):.1f}' r='3' fill='{color}' />"
        for i, v in enumerate(vals)
    )
    return (
        f"<svg width='{w}' height='{h}' role='img' aria-label='{key} trend'>"
        f"<polyline fill='none' stroke='{color}' stroke-width='2' points='{' '.join(pts)}' />"
        f"{dots}</svg>"
    )


def _finding_rows(runs: list[RunSummary]) -> str:
    rows: list[str] = []
    for summary in reversed(runs):  # newest first
        for f in summary.findings:
            rows.append(
                "<tr>"
                f"<td><code>{_esc(summary.run_id)}</code></td>"
                f"<td><code>{_esc(f.test_id)}</code></td>"
                f"<td>{_esc(f.category)}</td>"
                f"<td><span class='badge b-{_esc(f.severity.value)}'>{_esc(f.severity.value)}</span></td>"
                f"<td>{_esc(f.title)}</td>"
                "</tr>"
            )
    if not rows:
        return "<p class='muted'>No findings recorded across runs.</p>"
    return (
        "<table><thead><tr><th>Run</th><th>Test</th><th>Category</th>"
        "<th>Severity</th><th>Finding</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _history_rows(runs: list[RunSummary]) -> str:
    rows: list[str] = []
    for s in reversed(runs):
        m = s.metrics
        wr_pct = m.pass_rate
        rows.append(
            "<tr>"
            f"<td><code>{_esc(s.run_id)}</code></td>"
            f"<td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(s.created_at))}</td>"
            f"<td>{_esc(s.target)}</td>"
            f"<td>{m.total_cases}</td>"
            f"<td>{m.violations}</td>"
            f"<td>{_pct(m.attack_success_rate)}</td>"
            f"<td>{_pct(m.pass_rate)}"
            f"<div class='bar'><div class='{'ok' if wr_pct >= 0.5 else ''}' "
            f"style='width:{wr_pct * 100:.0f}%'></div></div></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Run</th><th>Date</th><th>Target</th><th>Cases</th>"
        "<th>Violations</th><th>ASR</th><th>Pass rate</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _latest_categories(runs: list[RunSummary]) -> str:
    if not runs:
        return (
            "<p class='muted'>No runs yet. Generate one with: "
            "agent-redteam run --suite core --target mock:weak</p>"
        )
    latest = runs[-1]
    rows: list[str] = []
    for cat, st in sorted(latest.metrics.by_category.items()):
        rate = float(st.get("violation_rate", 0.0))
        rows.append(
            "<tr>"
            f"<td>{_esc(cat)}</td>"
            f"<td>{int(st['total'])}</td>"
            f"<td>{int(st['violations'])}</td>"
            f"<td>{int(st['errors'])}</td>"
            f"<td>{_pct(rate)}"
            "<div class='bar'><div class='"
            + ("ok' " if rate == 0 else "' ")
            + f"style='width:{rate * 100:.0f}%'></div></div></td>"
            "</tr>"
        )
    return (
        f"<p class='muted'>Latest run: <code>{_esc(latest.run_id)}</code> "
        f"against <code>{_esc(latest.target)}</code></p>"
        "<table><thead><tr><th>Category</th><th>Total</th><th>Violations</th>"
        "<th>Errors</th><th>Violation rate</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def generate_dashboard(runs_dir: str | Path, out_path: str | Path) -> Path:
    runs = discover_runs(runs_dir)
    total_violations = sum(r.metrics.violations for r in runs)
    total_cases = sum(r.metrics.total_cases for r in runs)
    latest = runs[-1] if runs else None

    parts: list[str] = []
    parts.append(
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Agent Red-Team Evaluation Dashboard</title>"
        f"<style>{_CSS}</style></head><body>"
    )
    parts.append("<h1>Agent Red-Team Evaluation Dashboard</h1>")
    parts.append(
        f"<p class='muted'>Generated {time.strftime('%Y-%m-%d %H:%M:%S')} &middot; "
        f"{len(runs)} run(s) read from <code>{_esc(runs_dir)}/</code> (read-only)</p>"
    )
    parts.append(
        "<div class='cards'>"
        f"<div class='card'><div class='num'>{len(runs)}</div><div class='lbl'>Runs</div></div>"
        f"<div class='card'><div class='num'>{total_cases}</div><div class='lbl'>Cases executed</div></div>"
        f"<div class='card'><div class='num'>{total_violations}</div><div class='lbl'>Violations</div></div>"
        + (
            f"<div class='card'><div class='num'>{_pct(latest.metrics.attack_success_rate)}</div>"
            f"<div class='lbl'>Latest ASR</div></div>"
            f"<div class='card'><div class='num'>{_pct(latest.metrics.pass_rate)}</div>"
            f"<div class='lbl'>Latest pass rate</div></div>"
            if latest
            else ""
        )
        + "</div>"
    )

    parts.append("<h2>History</h2>")
    parts.append(_history_rows(runs) if runs else "<p class='muted'>No runs yet.</p>")

    parts.append("<h2>Trends</h2>")
    parts.append("<h3 class='muted'>Attack success rate</h3>")
    parts.append(_trend_svg(runs, "attack_success_rate", "#f85149"))
    parts.append("<h3 class='muted'>Pass rate</h3>")
    parts.append(_trend_svg(runs, "pass_rate", "#3fb950"))

    parts.append("<h2>Latest run by category</h2>")
    parts.append(_latest_categories(runs))

    parts.append("<h2>Findings (newest first)</h2>")
    parts.append(_finding_rows(runs))

    parts.append(
        "<footer>Generated by the Agent Red-Teaming &amp; Evaluation Framework. "
        "Static, local, read-only view over runs/ artifacts &mdash; no data leaves this machine.</footer>"
    )
    parts.append("</body></html>")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(parts), encoding="utf-8")
    return out
