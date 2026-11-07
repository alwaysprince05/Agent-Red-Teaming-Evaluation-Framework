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
from agent_redteam.core.runner import shorten_text
from agent_redteam.core.schemas import RunSummary

_REPLY_CHARS = 180
_PALETTE = ("#f0883e", "#58a6ff", "#a371f7", "#3fb950", "#d4a72c", "#ff7b72")
_ROUND_RE = re.compile(r"round(\d+)_")
#: Adaptive runs from before per-session suite folders (v2.0.2) cannot be grouped.
LEGACY_SESSION = "(older, not recorded)"
NO_REPLY = "<span class='muted'>(no reply recorded)</span>"

_CSS = """
:root { color-scheme: dark; --bg:#0b0e13; --panel:#12171e; --raise:#171d26; --line:#232b36; --grid:#1c232d;
        --text:#e8edf2; --text2:#b9c2cc; --muted:#7f8a96; --accent:#8aa4ff; --bad:#ff6b5e; --ok:#3fb950;
        --warn:#d4a72c; }
@media (prefers-color-scheme: light) {
  :root { color-scheme: light; --bg:#f5f7f9; --panel:#ffffff; --raise:#f0f3f6; --line:#dde3e9;
          --grid:#e9edf1; --text:#1b2027; --text2:#3d4652; --muted:#66717d; --accent:#3d5afe;
          --bad:#d1242f; --ok:#1a7f37; --warn:#9a6700; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); line-height: 1.5;
       font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
.wrap { max-width: 1160px; margin: 0 auto; padding: 0 1.5rem; }
header.top { border-bottom: 1px solid var(--line); background: var(--panel); }
header.top .wrap { display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between;
                   gap: 1rem 2rem; padding-top: 1.4rem; padding-bottom: 1.3rem; }
h1 { font-size: 1.45rem; margin: 0; letter-spacing: -.01em; }
header.top .intro { flex: 1 1 420px; min-width: 0; }
header.top .chips { flex: 0 1 auto; justify-content: flex-end; }
.tagline { color: var(--muted); margin: .2rem 0 0; font-size: .92rem; max-width: 62ch; }
.chips { display: flex; flex-wrap: wrap; gap: .4rem; }
.chip { border: 1px solid var(--line); border-radius: 999px; padding: .1rem .65rem; font-size: .76rem;
        color: var(--text2); background: var(--bg); white-space: nowrap; }
main.wrap { padding-top: 1.8rem; padding-bottom: 2rem; }
section { margin-top: 2.6rem; }
h2 { font-size: 1.05rem; margin: 0 0 .2rem; }
p.lead { color: var(--muted); margin: 0 0 .9rem; font-size: .9rem; max-width: 75ch; }
.muted { color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 1.2rem 1.4rem;
         overflow-x: auto; }
.hero { display: grid; grid-template-columns: 1fr 230px; gap: 1.5rem 2.5rem; align-items: center; }
.kicker { color: var(--muted); font-size: .74rem; font-weight: 650; letter-spacing: .08em;
          text-transform: uppercase; margin-bottom: .5rem; }
.trow { display: grid; grid-template-columns: 170px 1fr 120px; gap: 1rem; align-items: center;
        padding: .55rem 0; }
.trow .name { font-weight: 650; }
.trow .model { color: var(--muted); font-size: .76rem; }
.trow .model code { font-size: .95em; }
.track { background: var(--raise); border-radius: 999px; height: 12px; overflow: hidden; }
.track > div { height: 100%; border-radius: 999px; }
.trow .pct { font-size: 1.5rem; font-weight: 750; text-align: right; font-variant-numeric: tabular-nums; }
.trow .of { color: var(--muted); font-size: .76rem; text-align: right; }
.delta { border-left: 1px solid var(--line); padding-left: 2rem; }
.delta .big { font-size: 2.9rem; font-weight: 800; line-height: 1; color: var(--ok);
              font-variant-numeric: tabular-nums; letter-spacing: -.02em; }
.delta .big small { font-size: 1.1rem; font-weight: 700; }
.delta .cap { color: var(--text2); font-size: .85rem; margin-top: .5rem; }
.strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-top: 1rem;
         border: 1px solid var(--line); border-radius: 14px; background: var(--panel); overflow: hidden; }
.strip > div { padding: .85rem 1.2rem; border-right: 1px solid var(--line); }
.strip > div:last-child { border-right: 0; }
.strip .num { font-size: 1.45rem; font-weight: 750; font-variant-numeric: tabular-nums; }
.strip .lbl { color: var(--muted); font-size: .78rem; }
.strip .alert .num { color: var(--bad); }
.footnote { color: var(--muted); font-size: .8rem; margin: .6rem .2rem 0; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
th, td { border-bottom: 1px solid var(--grid); padding: .6rem .65rem; text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: .72rem; text-transform: uppercase;
     letter-spacing: .06em;
     border-bottom-color: var(--line); }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: var(--raise); }
.badge { display: inline-block; border-radius: 999px; padding: .1rem .55rem; font-size: .72rem;
         font-weight: 650;
         white-space: nowrap; border: 1px solid transparent; }
.b-critical { background: rgba(255,107,94,.13); color: var(--bad); border-color: rgba(255,107,94,.3); }
.b-high { background: rgba(240,136,62,.13); color: #e07b39; border-color: rgba(240,136,62,.3); }
.b-medium { background: rgba(212,167,44,.13); color: var(--warn); border-color: rgba(212,167,44,.3); }
.b-low { background: rgba(63,185,80,.13); color: var(--ok); border-color: rgba(63,185,80,.3); }
.b-fixed { background: rgba(88,166,255,.12); color: #4c9aff; border-color: rgba(88,166,255,.3); }
.b-adaptive { background: rgba(163,113,247,.13); color: #a371f7; border-color: rgba(163,113,247,.3); }
.b-leak { background: var(--bad); color: #fff; }
.bar { background: var(--raise); border-radius: 999px; height: 6px; overflow: hidden; margin-top: .35rem;
       min-width: 90px; }
.bar > div { height: 100%; background: var(--bad); border-radius: 999px; }
.path { display: flex; flex-wrap: wrap; align-items: center; gap: .35rem; }
.step { background: var(--raise); border: 1px solid var(--line); border-radius: 8px; padding: .15rem .55rem;
        font-size: .8rem; white-space: nowrap; }
.step b { color: var(--bad); font-weight: 650; }
.step.clean b { color: var(--ok); }
.arrow { color: var(--muted); }
tr.sev-critical td:first-child { box-shadow: inset 3px 0 0 var(--bad); }
tr.sev-high td:first-child { box-shadow: inset 3px 0 0 #e07b39; }
tr.sev-medium td:first-child { box-shadow: inset 3px 0 0 var(--warn); }
tr.sev-low td:first-child { box-shadow: inset 3px 0 0 var(--ok); }
tr.leak { background: rgba(255,107,94,.06); }
.reply { color: var(--text2); font-size: .85rem; border-left: 2px solid var(--line); padding-left: .6rem; }
.legend { display: flex; flex-wrap: wrap; gap: 1.1rem; font-size: .85rem; margin: 0 0 .6rem;
          color: var(--text2); }
.legend i { display: inline-block; width: .75rem; height: .75rem; border-radius: 3px; margin-right: .4rem;
            vertical-align: -1px; }
svg .grid { stroke: var(--grid); }
svg .axis { fill: var(--muted); font-size: 11px; }
svg .cat { fill: var(--text); font-size: 12.5px; }
svg .val { fill: var(--text2); font-size: 11px; font-weight: 600; }
.note { border-left: 3px solid var(--warn); padding: .55rem .9rem; color: var(--text2); font-size: .85rem;
        background: rgba(212,167,44,.07); border-radius: 0 8px 8px 0; margin: 0 0 .9rem; }
footer { margin-top: 3rem; padding-top: 1.1rem; border-top: 1px solid var(--line); color: var(--muted);
         font-size: .8rem; display: flex; flex-wrap: wrap; gap: .4rem 1.2rem;
         justify-content: space-between; }
.nowrap { white-space: nowrap; }
.who { font-weight: 600; white-space: nowrap; }
.who .badge { margin-left: .3rem; }
details.reply summary { cursor: pointer; list-style: none; }
details.reply summary::-webkit-details-marker { display: none; }
details.reply summary .more { color: var(--accent); font-size: .78rem; margin-left: .3rem;
                              white-space: nowrap; }
details.reply[open] summary .short { display: none; }
details.reply:not([open]) .full { display: none; }
details.reply[open] summary .more::after { content: 'show less'; }
details.reply:not([open]) summary .more::after { content: 'show full reply'; }
.chart svg { min-width: 560px; }
@media (max-width: 760px) {
  .wrap { padding: 0 1rem; }
  .hero { grid-template-columns: 1fr; }
  .delta { border-left: 0; border-top: 1px solid var(--line); padding: 1rem 0 0; }
  .trow { grid-template-columns: 1fr 120px; }
  .trow .track { grid-column: 1 / -1; grid-row: 2; }
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


def _display(target: str) -> tuple[str, str]:
    """('Weak agent', 'llm · qwen2.5:3b') for 'llm:weak@qwen2.5:3b'; other targets are shown as-is."""
    base, _, model = target.partition("@")
    kind, _, profile = base.partition(":")
    if kind in ("llm", "mock") and profile:
        return f"{profile.capitalize()} agent", f"{kind} · {model}" if model else kind
    return target, ""


def _legend(ranked: list[tuple[str, RunView, str]]) -> str:
    items = "".join(
        f"<span title='{_esc(t)}'><i style='background:{c}'></i>{_esc(_display(t)[0])}</span>"
        for t, _, c in ranked
    )
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
    rows = []
    for target, v, color in ranked:
        m = v.summary.metrics
        name, _ = _display(target)
        rows.append(
            "<div class='trow'>"
            f"<div><div class='name'>{_esc(name)}</div>"
            f"<div class='model'><code>{_esc(target)}</code></div></div>"
            f"<div class='track'><div style='width:{m.attack_success_rate * 100:.1f}%;background:{color}'>"
            "</div></div>"
            f"<div><div class='pct'>{_pct(m.attack_success_rate)}</div>"
            f"<div class='of'>{m.violations} of {m.executed} attacks</div></div>"
            "</div>"
        )
    delta = ""
    if len(ranked) >= 2:
        (worst, wv, _), (best, bv, _) = ranked[0], ranked[-1]
        gap = (wv.summary.metrics.attack_success_rate - bv.summary.metrics.attack_success_rate) * 100
        same = wv.summary.metrics.executed == bv.summary.metrics.executed
        attacks = f"the same {bv.summary.metrics.executed} attacks" if same else "the fixed suite"
        delta = (
            f"<div class='delta'><div class='big'>{gap:.1f}<small> pts lower</small></div>"
            f"<div class='cap'>Attack success of <b>{_esc(_display(best)[0])}</b> vs "
            f"<b>{_esc(_display(worst)[0])}</b> on {attacks}.</div></div>"
        )
    hero = ""
    if ranked:
        hero = (
            "<div class='panel hero'><div>"
            "<div class='kicker'>Attack success rate &middot; lower is safer</div>"
            f"{''.join(rows)}</div>{delta}</div>"
        )
    findings = [f for v in views for f in v.summary.findings]
    leaks = sum(1 for f in findings if _is_leak(f))
    executed = sum(v.summary.metrics.executed for v in views)
    violations = sum(v.summary.metrics.violations for v in views)
    rounds = sum(1 for v in views if v.kind == "adaptive")
    sessions = len({v.session for v in views if v.kind == "adaptive"})
    strip = (
        "<div class='strip'>"
        f"<div class='{'alert' if leaks else ''}'><div class='num'>{leaks}</div>"
        "<div class='lbl'>Proven leaks (canary secret in a reply)</div></div>"
        f"<div><div class='num'>{violations} <span class='muted'>/ {executed}</span></div>"
        f"<div class='lbl'>Violations across all {len(views)} runs</div></div>"
        f"<div><div class='num'>{rounds}</div><div class='lbl'>AI-planned rounds in {sessions} "
        f"session{'s' if sessions != 1 else ''}</div></div>"
        "</div>"
    )
    note = (
        "<p class='footnote'>Each agent's numbers come from its latest fixed-suite run, so agents are "
        "compared on identical attacks. Adaptive rounds use different, AI-written attacks and are shown "
        "separately below.</p>"
    )
    return f"{hero}{strip}{note}"


def _category_chart(views: list[RunView]) -> str:
    ranked = _ranked_targets(views)
    if not ranked:
        return "<p class='muted'>No fixed-suite runs yet.</p>"

    def rate(v: RunView, cat: str) -> float:
        return float(v.summary.metrics.by_category.get(cat, {}).get("violation_rate", 0.0))

    cats = sorted(
        {c for _, v, _ in ranked for c in v.summary.metrics.by_category},
        key=lambda c: (-max(rate(v, c) for _, v, _ in ranked), c),
    )
    n = len(ranked)
    bar_h, gap, pad = 11, 4, 16
    row_h = n * bar_h + (n - 1) * gap + pad * 2
    w, left, right, top = 760, 200, 60, 24
    plot_w = w - left - right
    h = top + row_h * len(cats) + 4
    out = [
        f"<svg viewBox='0 0 {w} {h}' width='100%' role='img' "
        "aria-label='Violation rate per category, by target'>"
    ]
    for frac in (0, 0.5, 1):
        x = left + plot_w * frac
        out.append(f"<line class='grid' x1='{x:.1f}' x2='{x:.1f}' y1='{top - 6}' y2='{h - 2}' />")
        out.append(
            f"<text class='axis' x='{x:.1f}' y='{top - 10}' text-anchor='middle'>{int(frac * 100)}%</text>"
        )
    for ci, cat in enumerate(cats):
        y0 = top + ci * row_h
        if ci:
            out.append(f"<line class='grid' x1='0' x2='{w}' y1='{y0:.1f}' y2='{y0:.1f}' />")
        out.append(
            f"<text class='cat' x='0' y='{y0 + row_h / 2 + 4:.1f}'>"
            f"{_esc(cat.replace('_', ' ').capitalize())}</text>"
        )
        for ti, (target, v, color) in enumerate(ranked):
            r = rate(v, cat)
            y = y0 + pad + ti * (bar_h + gap)
            bw = max(plot_w * r, 2)
            faded = "" if r else " opacity='.45'"
            out.append(
                f"<rect x='{left}' y='{y:.1f}' width='{bw:.1f}' height='{bar_h}' rx='3' "
                f"fill='{color}'{faded}>"
                f"<title>{_esc(target)} · {_esc(cat)}: {_pct(r)}</title></rect>"
            )
            out.append(
                f"<text class='val' x='{left + bw + 6:.1f}' y='{y + bar_h - 2:.1f}'>{r * 100:.0f}%</text>"
            )
    out.append("</svg>")
    return f"<div class='panel chart'>{_legend(ranked)}{''.join(out)}</div>"


def _has_trend(views: list[RunView]) -> bool:
    """A trend needs at least one target with two or more fixed-suite runs."""
    counts: dict[str, int] = {}
    for v in views:
        if v.kind == "fixed":
            counts[v.summary.target] = counts.get(v.summary.target, 0) + 1
    return any(n >= 2 for n in counts.values())


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
            f"<td class='nowrap'><code>{_esc(s.run_id)}</code></td>"
            f"<td>{_type_badge(v)}</td>"
            f"<td class='nowrap'>{time.strftime('%Y-%m-%d %H:%M', time.localtime(s.created_at))}</td>"
            f"<td class='nowrap'>{_esc(s.target)}</td>"
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
            f"<tr><td class='nowrap'><code>{_esc(sid)}</code></td>"
            f"<td class='nowrap'>{_esc(rounds[0].summary.target)}</td>"
            f"<td>{len(rounds)}</td><td>{cats}</td><td>{total_v} / {total_e}</td></tr>"
        )
    return (
        "<div class='panel'><table><thead><tr><th>Session</th><th>Target</th><th>Rounds</th>"
        "<th>Categories the planner chose (violations/attacks)</th><th>Total</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _finding_title(title: str) -> str:
    """Older runs stored titles cut mid-word at 80 characters; trim those to a whole word."""
    category, sep, objective = title.partition(": ")
    if sep and len(objective) == 80:
        return f"{category}: {shorten_text(objective, 79)}"
    return title


def _reply_cell(reply: str) -> str:
    """The reply, with long ones collapsed to a preview that expands without JavaScript."""
    if not reply:
        return f"<div class='reply'>{NO_REPLY}</div>"
    if len(reply) <= _REPLY_CHARS:
        return f"<div class='reply'>{_esc(reply)}</div>"
    return (
        "<details class='reply'><summary>"
        f"<span class='short'>{_esc(shorten_text(reply, _REPLY_CHARS))}</span><span class='more'></span>"
        f"</summary><div class='full'>{_esc(reply)}</div></details>"
    )


def _findings(views: list[RunView]) -> str:
    rows: list[str] = []
    for v in reversed(views):  # newest first
        for f in v.summary.findings:
            reply = v.replies.get(f.test_id, "")
            evidence = "; ".join(e.detail for e in f.evidence[:2])
            leak = " <span class='badge b-leak'>proven leak</span>" if _is_leak(f) else ""
            row_cls = f"sev-{_esc(f.severity.value)}" + (" leak" if _is_leak(f) else "")
            rows.append(
                f"<tr class='{row_cls}'>"
                f"<td class='nowrap'><code>{_esc(f.test_id)}</code></td>"
                f"<td><div class='who' title='{_esc(v.summary.target)} · run {_esc(v.summary.run_id)}'>"
                f"{_esc(_display(v.summary.target)[0])}</div>{_type_badge(v)}</td>"
                f"<td><span class='badge b-{_esc(f.severity.value)}'>{_esc(f.severity.value)}</span>{leak}"
                f"<div class='muted'>{_esc(f.category)}</div></td>"
                f"<td>{_esc(_finding_title(f.title))}</td>"
                f"<td>{_reply_cell(reply)}</td>"
                f"<td class='muted'>{_esc(evidence)}</td>"
                "</tr>"
            )
    if not rows:
        return "<p class='muted'>No findings recorded across runs.</p>"
    return (
        "<div class='panel'><table><thead><tr><th>Test</th><th>Agent</th><th>Severity</th><th>Finding</th>"
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
        "<header class='top'><div class='wrap'><div class='intro'>"
        "<h1>Agent Red-Team Evaluation Dashboard</h1>"
        "<p class='tagline'>How often adversarial attacks succeeded against each AI agent, what the AI "
        "attacker tried, and the evidence for every failure.</p></div>"
        f"<div class='chips'><span class='chip'>agent-redteam v{_esc(__version__)}</span>"
        f"<span class='chip'>{len(views)} run(s) &middot; <code>{_esc(runs_dir)}/</code></span>"
        f"<span class='chip'>{generated}</span><span class='chip'>Offline &middot; read-only</span>"
        "</div></div></header><main class='wrap'>",
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
            _headline(views),
            section(
                "Where each agent fails",
                "Share of attacks that succeeded in each category, most vulnerable first.",
                _category_chart(views),
            ),
            section("Runs", "", _runs_table(views)),
            section(
                "Adaptive sessions",
                "Each session is a closed loop: the planner picks a category, attacks are generated and "
                "run, and the results feed the next round.",
                _sessions(views),
            ),
        ]
        if _has_trend(views):
            parts.append(
                section(
                    "Fixed-suite attack success over time",
                    "One line per target; adaptive rounds are excluded because they use fewer, "
                    "different attacks.",
                    _trend_svg(views),
                )
            )
        parts += [
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
