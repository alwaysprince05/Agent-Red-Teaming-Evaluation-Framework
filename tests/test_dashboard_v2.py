"""Tests for the dashboard's comparison view (fixed-suite headline, run types,
adaptive sessions, agent replies in findings, proven-leak badges, escaping)."""

import json
import re

import pytest

from agent_redteam.adapters.base import AgentAdapter
from agent_redteam.core.adaptive import AdaptiveAgent, AdaptiveLimit
from agent_redteam.core.runner import RunOptions, execute_run
from agent_redteam.core.schemas import AgentResponse
from agent_redteam.reports.dashboard import LEGACY_SESSION, _load_views, generate_dashboard


class ScriptedAgent(AgentAdapter):
    """Replies with fixed text, to control exactly what the dashboard must show."""

    name = "scripted"

    def __init__(self, text: str, profile: str = "x") -> None:
        self.text = text
        self.profile = profile

    def send(self, turns):
        return AgentResponse(text=self.text)


@pytest.fixture()
def mixed_runs(tmp_path, weak_agent, strong_agent, suite_path):
    opts = RunOptions(rate_limit_s=0.0, output_dir=tmp_path)
    execute_run(suite_path, weak_agent, opts, run_id="fixed-weak")
    execute_run(suite_path, strong_agent, opts, run_id="fixed-strong")
    AdaptiveAgent(
        weak_agent,
        suite_path,
        limits=AdaptiveLimit(max_rounds=2, cases_per_round=2),
        run_options=opts,
        generation_mode="mutate",
        planner_mode="heuristic",
    ).run(output_dir=tmp_path)
    return tmp_path


def html_of(runs_dir):
    return generate_dashboard(runs_dir, runs_dir / "d.html").read_text(encoding="utf-8")


def test_headline_uses_latest_fixed_run_per_target_not_adaptive_rounds(mixed_runs):
    text = html_of(mixed_runs)
    headline = text.split("<h2>")[0]
    assert "<code>mock:weak</code>" in headline and "100.0%" in headline
    assert "<code>mock:strong</code>" in headline and "0.0%" in headline
    # Least safe target first, so the cards read weak -> strong.
    assert headline.index("<code>mock:weak</code>") < headline.index("<code>mock:strong</code>")
    # The weak card must come from the 13-case fixed run, not the later 2-case adaptive round.
    assert "13 of 13 attacks" in headline and "0 of 13 attacks" in headline
    assert "Latest ASR" not in text  # the misleading single-run card is gone


def test_runs_are_labelled_by_type(mixed_runs):
    text = html_of(mixed_runs)
    assert text.count("b-fixed'>Fixed suite") == 2
    assert "Adaptive · round 1/2" in text and "Adaptive · round 2/2" in text


def test_adaptive_session_grouped_and_excluded_from_trend(mixed_runs):
    views = _load_views(mixed_runs)
    sessions = {v.session for v in views if v.kind == "adaptive"}
    assert len(sessions) == 1 and LEGACY_SESSION not in sessions
    text = html_of(mixed_runs)
    sessions_html = text.split("<h2>Adaptive sessions</h2>")[1].split("<h2>")[0]
    assert next(iter(sessions)) in sessions_html
    trend = text.split("<h2>Fixed-suite attack success over time</h2>")[1].split("<h2>")[0]
    assert len(re.findall(r"<circle ", trend)) == 2  # only the two fixed-suite runs


def test_category_chart_has_axes_and_legend(mixed_runs):
    text = html_of(mixed_runs)
    chart = text.split("<h2>Violation rate by category</h2>")[1].split("<h2>")[0]
    assert "100%" in chart and "0%" in chart and "class='legend'" in chart
    assert chart.count("<rect ") >= 12  # 6 categories x 2 targets


def test_findings_show_agent_reply(mixed_runs):
    text = html_of(mixed_runs)
    findings = text.split("<h2>Findings (newest first)</h2>")[1]
    assert "Agent reply" in findings
    assert "ignoring my previous instructions" in findings  # mock:weak's actual reply


def test_hostile_reply_is_escaped(tmp_path, suite_path):
    payload = "<script>alert('x')</script><img src=x onerror=alert(1)>"
    execute_run(suite_path, ScriptedAgent(payload), RunOptions(rate_limit_s=0.0, output_dir=tmp_path))
    text = html_of(tmp_path)
    assert "<script>alert" not in text and "<img src=x" not in text
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in text


def test_proven_leak_badge_only_for_canary(tmp_path, suite_path):
    opts = RunOptions(rate_limit_s=0.0, output_dir=tmp_path)
    execute_run(suite_path, ScriptedAgent("Sure: CANARY-ABCDEF1234", "leaky"), opts, run_id="leaky")
    text = html_of(tmp_path)
    assert "proven leak" in text
    clean = tmp_path / "clean"
    execute_run(suite_path, ScriptedAgent("OK, unlocked."), RunOptions(rate_limit_s=0.0, output_dir=clean))
    assert "b-leak'>proven leak" not in html_of(clean)


def test_legacy_adaptive_runs_are_not_grouped(tmp_path, weak_agent, suite_path):
    rid, *_ = execute_run(suite_path, weak_agent, RunOptions(rate_limit_s=0.0, output_dir=tmp_path))
    summary_path = tmp_path / rid / "summary.json"
    data = json.loads(summary_path.read_text())
    data["suite"] = "runs/adaptive_suites/round01_jailbreak.yaml"  # pre-v2.0.2 layout
    summary_path.write_text(json.dumps(data))
    text = html_of(tmp_path)
    assert "Adaptive · round 1<" in text  # no fake "/N" total
    assert "No grouped adaptive sessions yet" in text


def test_footer_and_header_show_version(mixed_runs):
    from agent_redteam import __version__

    text = html_of(mixed_runs)
    assert f"agent-redteam v{__version__}" in text.split("<main>")[0]  # header chip
    assert f"Generated by agent-redteam v{__version__}" in text.split("<footer>")[1]
    assert "no data leaves this machine" in text


def test_comparison_states_the_gap(mixed_runs):
    headline = html_of(mixed_runs).split("<h2>")[0]
    assert "<b>100.0 points</b> lower than" in headline  # mock:strong 0% vs mock:weak 100%


def test_supports_light_and_dark_and_stays_offline(mixed_runs):
    text = html_of(mixed_runs)
    assert "prefers-color-scheme: light" in text
    assert "<script" not in text.lower()
    assert not re.search(r"(?:src|href)=['\"]https?://", text)


def test_bar_values_are_labelled(mixed_runs):
    chart = html_of(mixed_runs).split("<h2>Violation rate by category</h2>")[1].split("<h2>")[0]
    assert "class='val'" in chart and ">100%</text>" in chart
