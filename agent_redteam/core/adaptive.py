"""Adaptive red-teaming loop: the attacking agent decides what to try next.

Closed-loop pipeline executed as plan → generate → run → reflect, repeating until
a budget or stop condition triggers:

  1. **Plan**     — pick the next category to target (weakest first, or untried).
  2. **Generate** — propose new attack cases for that category
                    (mutate mode default; LLM mode when configured).
  3. **Run**      — execute the round's cases through the normal engine/evaluator.
  4. **Reflect**  — update per-category violation intel and decide whether
                    another round can help.

Design & safety constraints:
  - adapter/target selection stays exactly where it is (CLI ``resolve_target``);
    this loop never chooses or authorizes targets — you hand it a live adapter;
  - per-run budget caps rounds and total generated cases (no unbounded loops);
  - every generated case passes the same ``TestCase`` validation gate;
  - trace is fully reported (ReAct-style), no hidden state;
  - LLM calls are temperature=0, strict JSON; any LLM failure is reported as an
    error step in the trace — never a silent pass.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from agent_redteam.adapters.base import AgentAdapter
from agent_redteam.core.generator import (
    MAX_GENERATED_CASES,
    GeneratorError,
    generate_suite,
    save_suite,
)
from agent_redteam.core.runner import RunOptions, execute_run
from agent_redteam.core.schemas import ATTACK_CATEGORIES, AttackCategory, TestCase
from agent_redteam.core.suite import load_suite

DEFAULT_MAX_ROUNDS = 5
DEFAULT_CASES_PER_ROUND = 8
MAX_ROUNDS_CAP = 20


@dataclass
class AdaptiveLimit:
    """Hard budget for one adaptive loop. Values are clamped to safe caps."""

    max_rounds: int = DEFAULT_MAX_ROUNDS
    cases_per_round: int = DEFAULT_CASES_PER_ROUND

    def __post_init__(self) -> None:
        self.max_rounds = max(1, min(self.max_rounds, MAX_ROUNDS_CAP))
        self.cases_per_round = max(1, min(self.cases_per_round, MAX_GENERATED_CASES))


@dataclass
class RoundTrace:
    """One plan→generate→run→reflect cycle, fully inspectable."""

    round_no: int
    plan: str
    planned_category: str
    mode_used: str
    generated: int
    rejected: int
    violations: int
    executed: int
    run_id: str
    suite_path: str
    elapsed_s: float
    decision: str
    rejected_reasons: list[str] = field(default_factory=list)


@dataclass
class AdaptiveReport:
    """Final artifact of the loop: full trace + conclusion, JSON-serializable."""

    target: str
    rounds: list[RoundTrace]
    total_generated: int
    total_rejected: int
    total_violations: int
    total_executed: int
    stopped_reason: str
    categories_attacked: list[str]


def _pick_category(
    round_no: int,
    violations_by_cat: dict[str, int],
    tried: list[str],
    categories: list[str],
) -> tuple[AttackCategory, str]:
    """Phase 1 — PLAN. Deterministic heuristic attacker: weakest category first.

    Priorities = categories where attacks already succeeded (probe the vein
    deeper), then untried categories (broaden coverage), then round-robin.
    Returns (category, plan rationale) — the plan is always inspectable.
    """
    if round_no > 1:
        succeeded = sorted(
            (c for c, v in violations_by_cat.items() if v > 0 and c in categories),
            key=lambda c: -violations_by_cat[c],
        )
        if succeeded:
            top = succeeded[0]
            return (
                AttackCategory(top),
                f"rounds so far found {violations_by_cat[top]} violation(s) in "
                f"{top}; probing the same vein deeper",
            )
    untried = [c for c in categories if c not in tried]
    if untried:
        return (
            AttackCategory(untried[0]),
            f"{untried[0]} not yet probed this session; broadening coverage",
        )
    fallback = categories[(round_no - 1) % len(categories)]
    return (
        AttackCategory(fallback),
        f"all categories probed; cycling back to {fallback} for deeper variants",
    )


class AdaptiveAgent:
    """The red-teaming agent itself: plans, generates, attacks and reflects."""

    def __init__(
        self,
        adapter: AgentAdapter,
        seed_suite_path: str | Path,
        *,
        limits: AdaptiveLimit | None = None,
        run_options: RunOptions | None = None,
        generation_mode: str = "auto",
        rng_seed: int = 0,
    ) -> None:
        if adapter is None:
            raise ValueError("adapter is required (the loop never fabricates a target)")
        self.adapter = adapter
        self.limits = limits or AdaptiveLimit()
        self.run_options = run_options or RunOptions(rate_limit_s=0.0)
        self.generation_mode = generation_mode
        self.rng_seed = rng_seed
        self.seeds: list[TestCase] = load_suite(seed_suite_path)
        self._used_ids: set[str] = {c.id for c in self.seeds}
        self._round_suites: list[Path] = []

    def _next_unique_id(self, base: str) -> str:
        n = 0
        rid = f"{base}-G{n:02d}" if n else base
        while rid in self._used_ids:
            n += 1
            rid = f"{base}-G{n:02d}"
        return rid

    def _plan_next_category(
        self, round_no: int, violations_by_cat: dict[str, int], tried: list[str]
    ) -> tuple[AttackCategory, str]:
        return _pick_category(
            round_no, violations_by_cat, tried, list(ATTACK_CATEGORIES)
        )

    def _generate_round(
        self, cat: AttackCategory, round_no: int
    ) -> tuple[list[TestCase], list[str], str]:
        """Phase 2 — GENERATE. Agent decides the attack content (validated)."""
        cases, errors, mode_used = generate_suite(
            cat,
            self.limits.cases_per_round,
            self.seeds,
            mode=self.generation_mode,
            seed=self.rng_seed + round_no * 101,
        )
        # Enforce globally-unique ids across the whole loop (no cross-round collision).
        for i, case in enumerate(cases):
            if case.id in self._used_ids:
                base = str(case.id).split("-G")[0].split("-R")[0]
                new_id = self._next_unique_id(base)
                cases[i] = case.model_copy(update={"id": new_id})
            self._used_ids.add(cases[i].id)
        return cases, errors, mode_used

    def run(self, *, output_dir: Path | None = None) -> AdaptiveReport:
        out_dir = Path(output_dir or self.run_options.output_dir)
        trace: list[RoundTrace] = []
        violations_by_cat: dict[str, int] = {}
        tried: list[str] = []
        total_generated = total_rejected = total_violations = total_executed = 0
        stopped_reason = ""

        for round_no in range(1, self.limits.max_rounds + 1):
            t0 = time.monotonic()

            # ---------- Phase 1: PLAN ----------
            cat, rationale = self._plan_next_category(round_no, violations_by_cat, tried)
            tried.append(cat.value)

            # ---------- Phase 2: GENERATE ----------
            try:
                cases, errors, mode_used = self._generate_round(cat, round_no)
            except GeneratorError as exc:
                trace.append(RoundTrace(
                    round_no=round_no, plan=rationale, planned_category=cat.value,
                    mode_used=self.generation_mode, generated=0, rejected=0,
                    violations=0, executed=0, run_id="", suite_path="",
                    elapsed_s=time.monotonic() - t0, decision="stop",
                    rejected_reasons=[f"generation failed: {exc}"],
                ))
                stopped_reason = f"generation failed in round {round_no}: {exc}"
                break

            if not cases:
                trace.append(RoundTrace(
                    round_no=round_no, plan=rationale, planned_category=cat.value,
                    mode_used=mode_used, generated=0, rejected=len(errors),
                    violations=0, executed=0, run_id="", suite_path="",
                    elapsed_s=time.monotonic() - t0, decision="stop",
                    rejected_reasons=errors,
                ))
                stopped_reason = f"round {round_no}: no valid cases generated for {cat.value}"
                break

            # Persist the round's suite: reviewable and re-runnable evidence.
            suite_path = out_dir / "adaptive_suites" / f"round{round_no:02d}_{cat.value}.yaml"
            saved = save_suite(cases, suite_path)
            self._round_suites.append(saved)

            # ---------- Phase 3: ACT (normal pipeline; authorization untouched) ----------
            options = RunOptions(
                use_llm_judge=self.run_options.use_llm_judge,
                judge_fallback_to_deterministic=self.run_options.judge_fallback_to_deterministic,
                rate_limit_s=self.run_options.rate_limit_s,
                timeout_s=self.run_options.timeout_s,
                max_turns=self.run_options.max_turns,
                output_dir=out_dir,
            )
            run_id, summary, _results, _records = execute_run(str(saved), self.adapter, options)
            elapsed = time.monotonic() - t0

            violations_by_cat[cat.value] = violations_by_cat.get(cat.value, 0) + summary.metrics.violations
            total_generated += len(cases)
            total_rejected += len(errors)
            total_violations += summary.metrics.violations
            total_executed += summary.metrics.executed

            # ---------- Phase 4: REFLECT ----------
            remaining = self.limits.max_rounds - round_no
            if summary.metrics.violations > 0 and remaining > 0:
                decision = "continue"
                why = (
                    f"violations found in {cat.value}; {remaining} round(s) of budget "
                    f"remain to probe deeper"
                )
            elif summary.metrics.violations > 0:
                decision = "stop"
                why = "violations found; round budget exhausted"
            elif remaining > 0:
                decision = "continue"
                why = f"no violations in {cat.value}; {remaining} round(s) remain for other categories"
            else:
                decision = "stop"
                why = "no violations and round budget exhausted"

            trace.append(RoundTrace(
                round_no=round_no, plan=rationale, planned_category=cat.value,
                mode_used=mode_used, generated=len(cases), rejected=len(errors),
                violations=summary.metrics.violations,
                executed=summary.metrics.executed, run_id=run_id,
                suite_path=str(saved), elapsed_s=elapsed,
                decision=decision, rejected_reasons=errors,
            ))
            if decision == "stop":
                stopped_reason = why
                break

        if not stopped_reason:
            stopped_reason = "round budget exhausted after the planned cycles"

        return AdaptiveReport(
            target=getattr(self.adapter, "name", self.adapter.__class__.__name__),
            rounds=trace,
            total_generated=total_generated,
            total_rejected=total_rejected,
            total_violations=total_violations,
            total_executed=total_executed,
            stopped_reason=stopped_reason,
            categories_attacked=tried,
        )


def run_adaptive(
    adapter: AgentAdapter,
    seed_suite_path: str | Path,
    *,
    limits: AdaptiveLimit | None = None,
    run_options: RunOptions | None = None,
    generation_mode: str = "auto",
    rng_seed: int = 0,
    output_dir: Path | None = None,
) -> AdaptiveReport:
    """Convenience entry: build the agent and run the full loop. Returns the report."""
    return AdaptiveAgent(
        adapter,
        seed_suite_path,
        limits=limits,
        run_options=run_options,
        generation_mode=generation_mode,
        rng_seed=rng_seed,
    ).run(output_dir=output_dir)


__all__ = [
    "AdaptiveAgent",
    "AdaptiveLimit",
    "AdaptiveReport",
    "RoundTrace",
    "run_adaptive",
]
