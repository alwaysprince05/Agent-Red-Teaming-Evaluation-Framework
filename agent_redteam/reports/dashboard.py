"""Dashboard — Builds a visual HTML dashboard from evaluation run data.

This file generates a single, self-contained HTML page (no JavaScript, no external
assets, nothing loaded from the network) that shows the evaluation results.

Dashboard sections:
  - Headline: fixed-suite attack success rate per target (e.g. weak vs strong),
    plus totals, proven canary leaks and adaptive sessions.
  - Category comparison: grouped bar chart of each target's violation rate per
    category, from its latest fixed-suite run.
  - Runs table: every run, labelled "Fixed suite" or "Adaptive · round N/M".
  - Adaptive sessions: each AI-planned session with its rounds.
  - Trend: fixed-suite attack success rate over time (adaptive rounds excluded,
    because a 4-case round is not comparable with a 13-case suite run).
  - Findings: every violation with the agent's actual reply and the evidence.

How it works:
  1. Scans the runs directory for <run>/summary.json (+ records.json for replies).
  2. Classifies each run as a fixed-suite run or an adaptive round.
  3. Renders everything into one dark-themed HTML page.

The dashboard is read-only: it never modifies run artifacts. All run data,
including model replies (untrusted text), is HTML-escaped.
"""

from __future__ import annotations

import html
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from agent_redteam.core.schemas import RunSummary

_REPLY_CHARS = 180
_PALETTE = ("#f0883e", "#58a6ff", "#a371f7", "#3fb950", "#d4a72c", "#ff7b72")
_ROUND_RE = re.compile(r"round(\d+)_")
#: Adaptive runs from before per-session suite folders (v2.0.2) cannot be grouped.
LEGACY_SESSION = "(older, not recorded)"
NO_REPLY = "<span class='muted'>(no reply recorded)</span>"

_CSS = """
:root { color-scheme: dark; --bg:#0d1117; --panel:#161b22; --line:#30363d; --text:#e6edf3;
        --muted:#8b949e; --bad:#f85149; --ok:#3fb950; }
* { box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.45; }
main { max-width: 1200px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2.2rem 0 .4rem; }
p.lead { color: var(--muted); margin: .2rem 0 1rem; max-width: 70ch; }
.muted { color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
         gap: .8rem; margin: 1rem 0; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: .9rem 1.1rem; }
.card .num { font-size: 1.7rem; font-weight: 700; }
.card .lbl { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }
.card .sub { color: var(--muted); font-size: .8rem; margin-top: .2rem; }
.card.hero { border-left: 4px solid var(--hero, var(--line)); }
.heroes { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
.heroes .num { font-size: 2.4rem; }
.card .target { margin-top: .15rem; word-break: break-all; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
         padding: 1rem; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { border-bottom: 1px solid var(--line); padding: .5rem .6rem; text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: .8rem; text-transform: uppercase;
     letter-spacing: .04em; }
.badge { display: inline-block; border-radius: 999px; padding: .1rem .6rem; font-size: .75rem;
         font-weight: 600; white-space: nowrap; }
.b-critical { background: #490202; color: #f85149; }
.b-high { background: #3a1d02; color: #f0883e; }
.b-medium { background: #33400a; color: #d4a72c; }
.b-low { background: #0f2f1f; color: #3fb950; }
.b-fixed { background: #0c2d6b; color: #79c0ff; }
.b-adaptive { background: #2a1b4a; color: #d2a8ff; }
.b-leak { background: #490202; color: #ffa198; }
.bar { background: #21262d; border-radius: 4px; height: 8px; overflow: hidden;
       margin-top: .25rem; min-width: 80px; }
.bar > div { height: 100%; background: var(--bad); }
.bar > div.ok { background: var(--ok); }
.reply { color: #c9d1d9; font-size: .85rem; }
.legend { display: flex; flex-wrap: wrap; gap: 1rem; font-size: .85rem; margin: .4rem 0; }
.legend i { display: inline-block; width: .8rem; height: .8rem; border-radius: 2px; margin-right: .35rem;
            vertical-align: -1px; }
.note { border-left: 3px solid #d4a72c; padding: .4rem .8rem; color: var(--muted); font-size: .85rem;
        background: #1c1a10; border-radius: 0 6px 6px 0; }
footer { margin-top: 3rem; color: var(--muted); font-size: .8rem; }
@media (max-width: 640px) { body { padding: 1rem; } }
"""


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _esc(s: object) -> str:
    return html.escape(str(s))


@dataclass
class RunView:
    """A run summary plus what the dashboard derives from its artifacts."""

    summary: RunSummary
    kind: str = "fixed"  # "fixed" | "adaptive"
    session: str = ""
    round_no: int = 0
    rounds_in_session: int = 0
    replies: dict[str, str] = field(default_factory=dict)


def discover_runs(runs_dir: str | Path) -> list[RunSummary]:
    """Load every valid run summary under runs_dir, oldest first."""
    return [v.summary for v in _load_views(runs_dir)]


def _classify(summary: RunSummary) -> tuple[str, str, int]:
    """(kind, session, round) from the suite path the run was executed from."""
    parts = Path(summary.suite).parts
    if "adaptive_suites" not in parts:
        return "fixed", "", 0
    idx = parts.index("adaptive_suites")
    rest = parts[idx + 1 :]
    session = rest[0] if len(rest) >= 2 else LEGACY_SESSION
    match = _ROUND_RE.search(Path(summary.suite).name)
    return "adaptive", session, int(match.group(1)) if match else 0


def _load_replies(run_dir: Path) -> dict[str, str]:
    path = run_dir / "records.json"
    replies: dict[str, str] = {}
    if not path.exists():
        return replies
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "test_id" in rec:
            replies[str(rec["test_id"])] = str(rec.get("response_text") or "")
    return replies


def _load_views(runs_dir: str | Path) -> list[RunView]:
    base = Path(runs_dir)
    if not base.exists():
        return []
    views: list[RunView] = []
    for run_dir in sorted(base.iterdir()):
        summary_path = run_dir / "summary.json"
        if not run_dir.is_dir() or not summary_path.exists():
            continue
        try:
            summary = RunSummary.model_validate_json(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue  # skip unreadable/corrupt artifacts rather than failing the page
        kind, session, round_no = _classify(summary)
        views.append(RunView(summary, kind, session, round_no, replies=_load_replies(run_dir)))
    views.sort(key=lambda v: v.summary.created_at)
    sizes: dict[str, int] = {}
    for v in views:
        if v.kind == "adaptive" and v.session != LEGACY_SESSION:
            sizes[v.session] = sizes.get(v.session, 0) + 1
    for v in views:
        v.rounds_in_session = sizes.get(v.session, 0) if v.kind == "adaptive" else 0
    return views


def _is_leak(finding) -> bool:
    return any("CANARY" in e.detail for e in finding.evidence)


def _type_badge(v: RunView) -> str:
    if v.kind == "fixed":
        return "<span class='badge b-fixed'>Fixed suite</span>"
    if v.round_no and v.rounds_in_session:
        label = f"Adaptive · round {v.round_no}/{v.rounds_in_session}"
    elif v.round_no:
        label = f"Adaptive · round {v.round_no}"
    else:
        label = "Adaptive"
    return f"<span class='badge b-adaptive'>{_esc(label)}</span>"


def _latest_fixed_by_target(views: list[RunView]) -> dict[str, RunView]:
    latest: dict[str, RunView] = {}
    for v in views:
        if v.kind == "fixed":
            latest[v.summary.target] = v  # views are oldest first, so the last one wins
    return latest


def _ranked_targets(views: list[RunView]) -> list[tuple[str, RunView, str]]:
    """Targets with their latest fixed run and colour, least safe first (e.g. weak, then strong).

    The same order and colours are used by every chart, so a target looks the same everywhere.
    """
    latest = _latest_fixed_by_target(views)
    order = sorted(latest, key=lambda t: (-latest[t].summary.metrics.attack_success_rate, t))
    return [(t, latest[t], _PALETTE[i % len(_PALETTE)]) for i, t in enumerate(order)]


def _legend(ranked: list[tuple[str, RunView, str]]) -> str:
    items = "".join(f"<span><i style='background:{c}'></i>{_esc(t)}</span>" for t, _, c in ranked)
    return f"<div class='legend'>{items}</div>"


def _y_axis(out: list[str], left: int, right: int, top: float, plot_h: float) -> None:
    for frac in (0, 0.5, 1):
        y = top + plot_h * (1 - frac)
        out.append(f"<line x1='{left}' x2='{right}' y1='{y:.1f}' y2='{y:.1f}' stroke='#30363d' />")
        out.append(
            f"<text x='{left - 6}' y='{y + 4:.1f}' fill='#8b949e' font-size='11' "
            f"text-anchor='end'>{int(frac * 100)}%</text>"
        )


def _headline(views: list[RunView]) -> str:
    heroes = [
        f"<div class='card hero' style='--hero:{color}'>"
        f"<div class='lbl'>Attack success</div>"
        f"<div class='num'>{_pct(v.summary.metrics.attack_success_rate)}</div>"
        f"<div class='target'><code>{_esc(target)}</code></div>"
        f"<div class='sub'>{v.summary.metrics.violations} of {v.summary.metrics.executed} attacks, "
        f"latest fixed-suite run</div></div>"
        for target, v, color in _ranked_targets(views)
    ]
    findings = [f for v in views for f in v.summary.findings]
    sessions = {v.session for v in views if v.kind == "adaptive"}
    totals = [
        (len(views), "Runs"),
        (sum(v.summary.metrics.executed for v in views), "Attacks executed"),
        (sum(v.summary.metrics.violations for v in views), "Violations"),
        (sum(1 for f in findings if _is_leak(f)), "Proven leaks (canary)"),
        (len(sessions), "Adaptive sessions"),
    ]
    small = "".join(
        f"<div class='card'><div class='num'>{n}</div><div class='lbl'>{_esc(label)}</div></div>"
        for n, label in totals
    )
    hero_row = f"<div class='cards heroes'>{''.join(heroes)}</div>" if heroes else ""
    return f"{hero_row}<div class='cards'>{small}</div>"


def _category_chart(views: list[RunView]) -> str:
    ranked = _ranked_targets(views)
    if not ranked:
        return "<p class='muted'>No fixed-suite runs yet.</p>"
    cats = sorted({c for _, v, _ in ranked for c in v.summary.metrics.by_category})
    w, h, left, bottom, top = 760, 260, 44, 56, 14
    plot_w, plot_h = w - left - 10, h - bottom - top
    group = plot_w / max(len(cats), 1)
    bar = min(28.0, (group - 12) / len(ranked))
    out = [
        f"<svg viewBox='0 0 {w} {h}' width='100%' role='img' "
        "aria-label='Violation rate per category, by target'>"
    ]
    _y_axis(out, left, w - 10, top, plot_h)
    for ci, cat in enumerate(cats):
        x0 = left + ci * group + (group - bar * len(ranked)) / 2
        for ti, (target, v, color) in enumerate(ranked):
            rate = float(v.summary.metrics.by_category.get(cat, {}).get("violation_rate", 0.0))
            bh = plot_h * rate
            out.append(
                f"<rect x='{x0 + ti * bar:.1f}' y='{top + plot_h - bh:.1f}' "
                f"width='{bar - 2:.1f}' height='{max(bh, 1):.1f}' fill='{color}' rx='2'>"
                f"<title>{_esc(target)} · {_esc(cat)}: {_pct(rate)}</title></rect>"
            )
        out.append(
            f"<text x='{left + ci * group + group / 2:.1f}' y='{h - bottom + 18}' fill='#c9d1d9' "
            f"font-size='11' text-anchor='middle'>{_esc(cat.replace('_', ' '))}</text>"
        )
    out.append("</svg>")
    return f"<div class='panel'>{_legend(ranked)}{''.join(out)}</div>"


def _trend_svg(views: list[RunView], w: int = 760, h: int = 160) -> str:
    """Fixed-suite attack success rate over time: one line per target, labelled axes."""
    runs = [v for v in views if v.kind == "fixed"]
    if len(runs) < 2:
        return "<p class='muted'>Not enough fixed-suite runs for a trend yet (need 2+).</p>"
    ranked = _ranked_targets(views)
    colors = {t: c for t, _, c in ranked}
    left, top, bottom = 44, 12, 22
    plot_w, plot_h = w - left - 16, h - top - bottom
    step = plot_w / (len(runs) - 1)
    out = [f"<svg viewBox='0 0 {w} {h}' width='100%' role='img' aria-label='attack success rate trend'>"]
    _y_axis(out, left, w - 16, top, plot_h)
    pos = {
        id(v): (left + i * step, top + plot_h * (1 - v.summary.metrics.attack_success_rate))
        for i, v in enumerate(runs)
    }
    for target, _, color in ranked:
        mine = [pos[id(v)] for v in runs if v.summary.target == target]
        if len(mine) > 1:
            points = " ".join(f"{x:.1f},{y:.1f}" for x, y in mine)
            out.append(f"<polyline fill='none' stroke='{color}' stroke-width='2' points='{points}' />")
    for v in runs:
        x, y = pos[id(v)]
        tip = f"{v.summary.run_id} · {v.summary.target}: {_pct(v.summary.metrics.attack_success_rate)}"
        color = colors.get(v.summary.target, "#8b949e")
        out.append(
            f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4' fill='{color}'><title>{_esc(tip)}</title></circle>"
        )
    out.append(f"<text x='{left}' y='{h - 4}' fill='#8b949e' font-size='11'>oldest</text>")
    out.append(
        f"<text x='{w - 16}' y='{h - 4}' fill='#8b949e' font-size='11' text-anchor='end'>newest</text>"
    )
    out.append("</svg>")
    return f"<div class='panel'>{_legend(ranked)}{''.join(out)}</div>"


def _runs_table(views: list[RunView]) -> str:
    rows: list[str] = []
    for v in reversed(views):
        s, m = v.summary, v.summary.metrics
        rows.append(
            "<tr>"
            f"<td><code>{_esc(s.run_id)}</code></td>"
            f"<td>{_type_badge(v)}</td>"
            f"<td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(s.created_at))}</td>"
            f"<td>{_esc(s.target)}</td>"
            f"<td>{m.violations} / {m.executed}</td>"
            f"<td>{_pct(m.attack_success_rate)}<div class='bar'>"
            f"<div style='width:{m.attack_success_rate * 100:.0f}%'></div></div></td>"
            f"<td>{m.errors}</td>"
            "</tr>"
        )
    return (
        "<div class='panel'><table><thead><tr><th>Run</th><th>Type</th><th>Date</th><th>Target</th>"
        "<th>Violations</th><th>Attack success</th><th>Errors</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _sessions(views: list[RunView]) -> str:
    sessions: dict[str, list[RunView]] = {}
    for v in views:
        if v.kind == "adaptive":
            sessions.setdefault(v.session, []).append(v)
    if not sessions:
        return (
            "<p class='muted'>No adaptive sessions yet. Run: agent-redteam adaptive --target llm:strong</p>"
        )
    rows: list[str] = []
    sessions.pop(LEGACY_SESSION, None)  # older rounds stay in the runs table, ungrouped
    if not sessions:
        return "<p class='muted'>No grouped adaptive sessions yet (older runs are listed under Runs).</p>"
    for sid, rounds in sorted(sessions.items(), reverse=True):
        rounds.sort(key=lambda r: r.round_no)
        cats = " → ".join(
            f"{_esc(next(iter(r.summary.metrics.by_category), '?'))} "
            f"({r.summary.metrics.violations}/{r.summary.metrics.executed})"
            for r in rounds
        )
        total_v = sum(r.summary.metrics.violations for r in rounds)
        total_e = sum(r.summary.metrics.executed for r in rounds)
        rows.append(
            f"<tr><td><code>{_esc(sid)}</code></td><td>{_esc(rounds[0].summary.target)}</td>"
            f"<td>{len(rounds)}</td><td>{cats}</td><td>{total_v} / {total_e}</td></tr>"
        )
    return (
        "<div class='panel'><table><thead><tr><th>Session</th><th>Target</th><th>Rounds</th>"
        "<th>Categories the planner chose (violations/attacks)</th><th>Total</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _findings(views: list[RunView]) -> str:
    rows: list[str] = []
    for v in reversed(views):  # newest first
        for f in v.summary.findings:
            reply = v.replies.get(f.test_id, "")
            if len(reply) > _REPLY_CHARS:
                reply = reply[:_REPLY_CHARS] + "…"
            evidence = "; ".join(e.detail for e in f.evidence[:2])
            leak = " <span class='badge b-leak'>proven leak</span>" if _is_leak(f) else ""
            rows.append(
                "<tr>"
                f"<td><code>{_esc(f.test_id)}</code>"
                f"<div class='muted'><code>{_esc(v.summary.run_id)}</code></div></td>"
                f"<td><span class='badge b-{_esc(f.severity.value)}'>{_esc(f.severity.value)}</span>{leak}"
                f"<div class='muted'>{_esc(f.category)}</div></td>"
                f"<td>{_esc(f.title)}</td>"
                f"<td class='reply'>{_esc(reply) or NO_REPLY}</td>"
                f"<td class='muted'>{_esc(evidence)}</td>"
                "</tr>"
            )
    if not rows:
        return "<p class='muted'>No findings recorded across runs.</p>"
    return (
        "<div class='panel'><table><thead><tr><th>Test</th><th>Severity</th><th>Finding</th>"
        "<th>Agent reply</th><th>Evidence</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def generate_dashboard(runs_dir: str | Path, out_path: str | Path) -> Path:
    views = _load_views(runs_dir)

    parts: list[str] = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Agent Red-Team Evaluation Dashboard</title>"
        f"<style>{_CSS}</style></head><body><main>",
        "<h1>Agent Red-Team Evaluation Dashboard</h1>",
        f"<p class='muted'>Generated {time.strftime('%Y-%m-%d %H:%M:%S')} &middot; "
        f"{len(views)} run(s) read from <code>{_esc(runs_dir)}/</code> (read-only)</p>",
    ]
    if not views:
        parts.append(
            "<p class='muted'>No runs yet. Generate one with: "
            "agent-redteam run --suite core --target mock:weak</p>"
        )
    else:
        parts += [
            "<p class='lead'>Headline numbers use each target's latest <b>fixed-suite</b> run, so targets "
            "are compared on the same attacks. Adaptive rounds are shown separately.</p>",
            _headline(views),
            "<h2>Violation rate by category</h2>",
            "<p class='lead'>Latest fixed-suite run per target. Lower is safer.</p>",
            _category_chart(views),
            "<h2>Runs</h2>",
            _runs_table(views),
            "<h2>Adaptive sessions</h2>",
            "<p class='lead'>Each session is a closed loop: the planner picks a category, attacks are "
            "generated and run, and the results feed the next round.</p>",
            _sessions(views),
            "<h2>Fixed-suite attack success over time</h2>",
            _trend_svg(views),
            "<h2>Findings (newest first)</h2>",
            "<p class='note'>Keyword grading can flag a polite decline that does not match a known refusal "
            "phrase. Read the agent reply before counting a finding; a <b>proven leak</b> badge means a "
            "planted canary secret appeared, which is never a false alarm.</p>",
            _findings(views),
        ]
    parts.append(
        "<footer>Generated by the Agent Red-Teaming &amp; Evaluation Framework. "
        "Static, local, read-only view over run artifacts &mdash; no data leaves this machine.</footer>"
        "</main></body></html>"
    )

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(parts), encoding="utf-8")
    return out
