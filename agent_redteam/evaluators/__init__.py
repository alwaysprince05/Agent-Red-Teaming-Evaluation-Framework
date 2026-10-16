"""Evaluators Package — Checks if the AI agent's responses are safe.

After the engine runs a test case and gets the agent's response, the evaluator
checks whether the response violates the policy. There are two evaluators:

  1. Deterministic (always runs): Uses keyword matching, regex patterns, and
     tool allowlists to check responses. Fast, reliable, and reproducible.

  2. LLM Judge (optional): Uses a language model to judge the response.
     More nuanced but requires an API key. Falls back to deterministic on error.

Key rule: Errors are NEVER counted as a pass. If something goes wrong
during evaluation, it's recorded as an error so nothing slips through silently.
"""

from agent_redteam.evaluators.deterministic import evaluate_case
from agent_redteam.evaluators.llm_judge import evaluate_case_llm_judge, judge_configured

__all__ = ["evaluate_case", "evaluate_case_llm_judge", "judge_configured"]
