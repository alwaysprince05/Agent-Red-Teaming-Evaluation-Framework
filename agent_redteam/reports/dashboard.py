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

from agent_redteam import __version__
from agent_redteam.core.schemas import RunSummary

_REPLY_CHARS = 180
_PALETTE = ("#f0883e", "#58a6ff", "#a371f7", "#3fb950", "#d4a72c", "#ff7b72")
_ROUND_RE = re.compile(r"round(\d+)_")
#: Adaptive runs from before per-session suite folders (v2.0.2) cannot be grouped.
LEGACY_SESSION = "(older, not recorded)"
NO_REPLY = "<span class='muted'>(no reply recorded)</span>"

_CSS = """
:root { color-scheme: dark; --bg:#0b0f14; --panel:#131a22; --panel2:#18212b; --line:#263140;
        --grid:#1f2833; --text:#e6edf3; --text2:#c9d1d9; --muted:#8b98a5; --accent:#7c9cff;
        --bad:#f85149; --ok:#3fb950; --warn:#d4a72c; --shadow:0 1px 2px rgba(0,0,0,.35); }
@media (prefers-color-scheme: light) {
  :root { color-scheme: light; --bg:#f6f8fa; --panel:#ffffff; --panel2:#f3f5f8; --line:#d8dee4;
          --grid:#e7ebef; --text:#1f2328; --text2:#31373e; --muted:#5d6670; --accent:#3d5afe;
          --bad:#cf222e; --ok:#1a7f37; --warn:#9a6700; --shadow:0 1px 2px rgba(31,35,40,.08); }
}
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       background: var(--bg); color: var(--text); margin: 0; line-height: 1.5; }
main { max-width: 1180px; margin: 0 auto; padding: 0 1.5rem 2rem; }
header.top { background: linear-gradient(135deg, rgba(124,156,255,.16), rgba(124,156,255,0) 60%);
             border-bottom: 1px solid var(--line); margin-bottom: 1.5rem; }
header.top .in { max-width: 1180px; margin: 0 auto; padding: 1.8rem 1.5rem 1.4rem; }
.eyebrow { color: var(--accent); font-size: .75rem; font-weight: 700; letter-spacing: .12em;
           text-transform: uppercase; }
h1 { font-size: 1.9rem; margin: .2rem 0 .3rem; letter-spacing: -.01em; }
.tagline { color: var(--muted); margin: 0 0 .9rem; max-width: 70ch; }
.chips { display: flex; flex-wrap: wrap; gap: .5rem; }
.chip { background: var(--panel); border: 1px solid var(--line); border-radius: 999px; padding: .15rem .7rem;
        font-size: .78rem; color: var(--text2); }
section { margin-top: 2.2rem; }
h2 { font-size: 1.15rem; margin: 0 0 .25rem; letter-spacing: -.005em; }
p.lead { color: var(--muted); margin: 0 0 .9rem; max-width: 75ch; font-size: .92rem; }
.muted { color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 1.1rem 1.2rem;
         overflow-x: auto; box-shadow: var(--shadow); }
.compare .row { display: grid; grid-template-columns: minmax(170px, 270px) 1fr 110px; gap: 1rem;
                align-items: center; padding: .7rem 0; border-bottom: 1px solid var(--grid); }
.compare .row:last-child, .compare .row:nth-last-child(2) { border-bottom: 0; }
.compare .who code { font-size: .9rem; color: var(--text); word-break: break-all; }
.compare .who .sub { color: var(--muted); font-size: .78rem; }
.compare .track { background: var(--panel2); border-radius: 999px; height: 14px; overflow: hidden; }
.compare .track > div { height: 100%; border-radius: 999px; }
.compare .big { font-size: 1.9rem; font-weight: 750; text-align: right; font-variant-numeric: tabular-nums; }
.compare .verdict { margin-top: .6rem; padding-top: .7rem; border-top: 1px solid var(--grid);
                    color: var(--text2);
                    font-size: .92rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: .8rem;
         margin-top: .9rem; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: .85rem 1rem;
        box-shadow: var(--shadow); }
.card .num { font-size: 1.6rem; font-weight: 700; font-variant-numeric: tabular-nums; }
.card .lbl { color: var(--muted); font-size: .74rem; text-transform: uppercase; letter-spacing: .06em; }
.card.alert .num { color: var(--bad); }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
th, td { border-bottom: 1px solid var(--grid); padding: .6rem .65rem; text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: .72rem; text-transform: uppercase;
     letter-spacing: .06em; border-bottom-color: var(--line); }
tbody tr:hover { background: var(--panel2); }
.badge { display: inline-block; border-radius: 999px; padding: .12rem .6rem; font-size: .72rem;
         font-weight: 650; white-space: nowrap; border: 1px solid transparent; }
.b-critical { background: rgba(248,81,73,.15); color: var(--bad); border-color: rgba(248,81,73,.35); }
.b-high { background: rgba(240,136,62,.15); color: #e07b39; border-color: rgba(240,136,62,.35); }
.b-medium { background: rgba(212,167,44,.15); color: var(--warn); border-color: rgba(212,167,44,.35); }
.b-low { background: rgba(63,185,80,.15); color: var(--ok); border-color: rgba(63,185,80,.35); }
.b-fixed { background: rgba(88,166,255,.14); color: #4c9aff; border-color: rgba(88,166,255,.35); }
.b-adaptive { background: rgba(163,113,247,.15); color: #a371f7; border-color: rgba(163,113,247,.35); }
.b-leak { background: var(--bad); color: #fff; }
.bar { background: var(--panel2); border-radius: 999px; height: 6px; overflow: hidden;
       margin-top: .35rem; min-width: 90px; }
.bar > div { height: 100%; background: var(--bad); border-radius: 999px; }
.path { display: flex; flex-wrap: wrap; align-items: center; gap: .35rem; }
.step { background: var(--panel2); border: 1px solid var(--line); border-radius: 8px; padding: .15rem .55rem;
        font-size: .8rem; white-space: nowrap; }
.step b { color: var(--bad); font-weight: 650; }
.step.clean b { color: var(--ok); }
.arrow { color: var(--muted); }
tr.sev-critical td:first-child { box-shadow: inset 3px 0 0 var(--bad); }
tr.sev-high td:first-child { box-shadow: inset 3px 0 0 #e07b39; }
tr.sev-medium td:first-child { box-shadow: inset 3px 0 0 var(--warn); }
tr.sev-low td:first-child { box-shadow: inset 3px 0 0 var(--ok); }
tr.leak { background: rgba(248,81,73,.07); }
.reply { color: var(--text2); font-size: .85rem; border-left: 2px solid var(--line); padding-left: .6rem; }
.legend { display: flex; flex-wrap: wrap; gap: 1.1rem; font-size: .85rem; margin: 0 0 .5rem;
          color: var(--text2); }
.legend i { display: inline-block; width: .75rem; height: .75rem; border-radius: 3px; margin-right: .4rem;
            vertical-align: -1px; }
svg .grid { stroke: var(--grid); }
svg .axis { fill: var(--muted); font-size: 11px; }
svg .cat { fill: var(--text2); font-size: 11.5px; }
svg .val { fill: var(--text2); font-size: 10px; font-weight: 600; }
.note { border-left: 3px solid var(--warn); padding: .55rem .9rem; color: var(--text2); font-size: .85rem;
        background: rgba(212,167,44,.08); border-radius: 0 8px 8px 0; margin: 0 0 .9rem; }
footer { margin-top: 3rem; padding-top: 1.2rem; border-top: 1px solid var(--line); color: var(--muted);
         font-size: .8rem; display: flex; flex-wrap: wrap; gap: .4rem 1.2rem;
         justify-content: space-between; }
@media (max-width: 720px) {
  main, header.top .in { padding-left: 1rem; padding-right: 1rem; }
  .compare .row { grid-template-columns: 1fr 90px; }
  .compare .track { grid-column: 1 / -1; grid-row: 2; }
}
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
        out.append(f"<line class='grid' x1='{left}' x2='{right}' y1='{y:.1f}' y2='{y:.1f}' />")
        out.append(
            f"<text class='axis' x='{left - 8}' y='{y + 4:.1f}' text-anchor='end'>{int(frac * 100)}%</text>"
        )


def _headline(views: list[RunView]) -> str:
    ranked = _ranked_targets(views)
    rows = "".join(
        "<div class='row'>"
        f"<div class='who'><code>{_esc(target)}</code>"
        f"<div class='sub'>{v.summary.metrics.violations} of {v.summary.metrics.executed} attacks "
        f"succeeded</div></div>"
        f"<div class='track'><div style='width:{v.summary.metrics.attack_success_rate * 100:.1f}%;"
        f"background:{color}'></div></div>"
        f"<div class='big'>{_pct(v.summary.metrics.attack_success_rate)}</div>"
        "</div>"
        for target, v, color in ranked
    )
    verdict = ""
    if len(ranked) >= 2:
        (worst, wv, _), (best, bv, _) = ranked[0], ranked[-1]
        gap = (wv.summary.metrics.attack_success_rate - bv.summary.metrics.attack_success_rate) * 100
        verdict = (
            f"<div class='verdict'><code>{_esc(best)}</code> is <b>{gap:.1f} points</b> lower than "
            f"<code>{_esc(worst)}</code> on the same attacks.</div>"
        )
    compare = (
        f"<div class='panel compare'><div class='eyebrow'>Attack success rate · lower is safer</div>"
        f"{rows}{verdict}</div>"
        if ranked
        else ""
    )
    findings = [f for v in views for f in v.summary.findings]
    sessions = {v.session for v in views if v.kind == "adaptive"}
    leaks = sum(1 for f in findings if _is_leak(f))
    totals = [
        (len(views), "Runs", False),
        (sum(v.summary.metrics.executed for v in views), "Attacks executed", False),
        (sum(v.summary.metrics.violations for v in views), "Violations", False),
        (leaks, "Proven leaks (canary)", leaks > 0),
        (len(sessions), "Adaptive sessions", False),
    ]
    small = "".join(
        f"<div class='card{' alert' if alert else ''}'><div class='num'>{n}</div>"
        f"<div class='lbl'>{_esc(label)}</div></div>"
        for n, label, alert in totals
    )
    return f"{compare}<div class='cards'>{small}</div>"


def _category_chart(views: list[RunView]) -> str:
    ranked = _ranked_targets(views)
    if not ranked:
        return "<p class='muted'>No fixed-suite runs yet.</p>"
    cats = sorted({c for _, v, _ in ranked for c in v.summary.metrics.by_category})
    w, h, left, bottom, top = 760, 270, 46, 50, 22
    plot_w, plot_h = w - left - 10, h - bottom - top
    group = plot_w / max(len(cats), 1)
    bar = min(40.0, (group - 16) / len(ranked))  # slot per target; the bar itself is narrower
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
            x = x0 + ti * bar
            out.append(
                f"<rect x='{x:.1f}' y='{top + plot_h - bh:.1f}' "
                f"width='{bar - 10:.1f}' height='{max(bh, 1):.1f}' fill='{color}' rx='3'>"
                f"<title>{_esc(target)} · {_esc(cat)}: {_pct(rate)}</title></rect>"
            )
            if rate > 0:
                out.append(
                    f"<text class='val' x='{x + (bar - 10) / 2:.1f}' y='{top + plot_h - bh - 5:.1f}' "
                    f"text-anchor='middle'>{rate * 100:.0f}%</text>"
                )
        out.append(
            f"<text class='cat' x='{left + ci * group + group / 2:.1f}' y='{h - bottom + 20}' "
            f"text-anchor='middle'>{_esc(cat.replace('_', ' '))}</text>"
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
            out.append(
                f"<polyline fill='none' stroke='{color}' stroke-width='2.5' stroke-linejoin='round' "
                f"points='{points}' />"
            )
    for v in runs:
        x, y = pos[id(v)]
        tip = f"{v.summary.run_id} · {v.summary.target}: {_pct(v.summary.metrics.attack_success_rate)}"
        color = colors.get(v.summary.target, "#8b949e")
        out.append(
            f"<circle cx='{x:.1f}' cy='{y:.1f}' r='5' fill='{color}' stroke='var(--panel)' stroke-width='2'>"
            f"<title>{_esc(tip)}</title></circle>"
        )
    out.append(f"<text class='axis' x='{left}' y='{h - 4}'>oldest</text>")
    out.append(f"<text class='axis' x='{w - 16}' y='{h - 4}' text-anchor='end'>newest</text>")
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
        cats = (
            "<div class='path'>"
            + "<span class='arrow'>→</span>".join(
                f"<span class='step{' clean' if not r.summary.metrics.violations else ''}'>"
                f"{_esc(next(iter(r.summary.metrics.by_category), '?').replace('_', ' '))} "
                f"<b>{r.summary.metrics.violations}/{r.summary.metrics.executed}</b></span>"
                for r in rounds
            )
            + "</div>"
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
            row_cls = f"sev-{_esc(f.severity.value)}" + (" leak" if _is_leak(f) else "")
            rows.append(
                f"<tr class='{row_cls}'>"
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

    generated = time.strftime("%Y-%m-%d %H:%M")
    parts: list[str] = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Agent Red-Team Evaluation Dashboard</title>"
        f"<style>{_CSS}</style></head><body>",
        "<header class='top'><div class='in'><div class='eyebrow'>Agent red-teaming report</div>"
        "<h1>Agent Red-Team Evaluation Dashboard</h1>"
        "<p class='tagline'>How often adversarial attacks succeeded against each AI agent, what the "
        "AI attacker tried, and the evidence for every failure.</p>"
        f"<div class='chips'><span class='chip'>agent-redteam v{_esc(__version__)}</span>"
        f"<span class='chip'>{len(views)} run(s) from <code>{_esc(runs_dir)}/</code></span>"
        f"<span class='chip'>Generated {generated}</span><span class='chip'>Read-only · offline</span>"
        "</div></div></header><main>",
    ]

    def section(title: str, lead: str, body: str) -> str:
        intro = f"<p class='lead'>{lead}</p>" if lead else ""
        return f"<section><h2>{title}</h2>{intro}{body}</section>"

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
            section(
                "Violation rate by category",
                "Latest fixed-suite run per target. Lower is safer.",
                _category_chart(views),
            ),
            section("Runs", "", _runs_table(views)),
            section(
                "Adaptive sessions",
                "Each session is a closed loop: the planner picks a category, attacks are generated and "
                "run, and the results feed the next round.",
                _sessions(views),
            ),
            section(
                "Fixed-suite attack success over time",
                "One line per target; adaptive rounds are excluded because they use fewer, "
                "different attacks.",
                _trend_svg(views),
            ),
            section(
                "Findings (newest first)",
                "",
                "<p class='note'>Keyword grading can flag a polite decline that does not match a known "
                "refusal phrase. Read the agent reply before counting a finding; a <b>proven leak</b> badge "
                "means a planted canary secret appeared, which is never a false alarm.</p>"
                + _findings(views),
            ),
        ]
    parts.append(
        f"<footer><span>Generated by agent-redteam v{_esc(__version__)} on {generated}.</span>"
        "<span>Static, local, read-only view over run artifacts &mdash; no data leaves this machine.</span>"
        "</footer></main></body></html>"
    )

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(parts), encoding="utf-8")
    return out
