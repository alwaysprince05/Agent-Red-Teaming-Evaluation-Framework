"""Pydantic schemas for test cases, executions, evaluations, findings and run summaries."""

from __future__ import annotations

import re
import time
import uuid
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

ATTACK_CATEGORIES = (
    "prompt_injection",
    "jailbreak",
    "data_leakage",
    "unsafe_tool_use",
    "multi_turn_manipulation",
    "indirect_injection",
)

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AttackCategory(StrEnum):
    prompt_injection = "prompt_injection"
    jailbreak = "jailbreak"
    data_leakage = "data_leakage"
    unsafe_tool_use = "unsafe_tool_use"
    multi_turn_manipulation = "multi_turn_manipulation"
    indirect_injection = "indirect_injection"


class EvaluationStatus(StrEnum):
    passed = "passed"
    violated = "violated"
    error = "error"
    skipped = "skipped"


class ExecStatus(StrEnum):
    ok = "ok"
    error = "error"
    timeout = "timeout"
    skipped = "skipped"


class Policy(BaseModel):
    """Declarative policy a target response (and trace) must satisfy."""

    must_not_contain: list[str] = Field(default_factory=list)
    must_contain: list[str] = Field(default_factory=list)
    must_not_match_regex: list[str] = Field(default_factory=list)
    must_match_regex: list[str] = Field(default_factory=list)
    # If set: tool names the agent is allowed to call during this case.
    tool_allowlist: list[str] | None = None
    # If set: the response must look like a refusal.
    must_refuse: bool = False

    @field_validator("must_not_match_regex", "must_match_regex")
    @classmethod
    def _valid_regex(cls, v: list[str]) -> list[str]:
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _non_empty(self) -> Policy:
        has_rule = (
            self.must_not_contain
            or self.must_contain
            or self.must_not_match_regex
            or self.must_match_regex
            or self.tool_allowlist is not None
            or self.must_refuse
        )
        if not has_rule:
            raise ValueError("policy must declare at least one rule")
        return self


class Turn(BaseModel):
    role: Literal["user", "system", "tool"] = "user"
    content: str


class TestCase(BaseModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,63}$")
    category: AttackCategory
    objective: str = Field(min_length=3, max_length=500)
    turns: list[Turn] = Field(min_length=1)
    policy: Policy
    severity_hint: Severity = Severity.medium
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("turns")
    @classmethod
    def _last_turn_is_user(cls, v: list[Turn]) -> list[Turn]:
        if v[-1].role != "user":
            raise ValueError("last turn must have role 'user' (the agent must be given something to answer)")
        return v

    @property
    def is_multi_turn(self) -> bool:
        return len(self.turns) > 1


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    latency_ms: float | None = None
    error: str | None = None


class ExecutionRecord(BaseModel):
    run_id: str
    test_id: str
    category: str
    started_at: float
    finished_at: float | None = None
    status: ExecStatus = ExecStatus.ok
    turns_sent: list[Turn] = Field(default_factory=list)
    response_text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    response_error: str | None = None
    latency_ms: float | None = None

    def finish(self, response: AgentResponse) -> None:
        self.finished_at = time.time()
        self.response_text = response.text
        self.tool_calls = response.tool_calls
        self.latency_ms = response.latency_ms
        self.response_error = response.error

    def mark(self, status: ExecStatus, error: str | None = None) -> None:
        self.finished_at = time.time()
        self.status = status
        if error is not None:
            self.response_error = error


class Evidence(BaseModel):
    kind: Literal["matched_rule", "judge_rationale", "tool_call", "regex_match", "note"]
    detail: str


class EvaluationResult(BaseModel):
    run_id: str
    test_id: str
    category: str
    status: EvaluationStatus
    violated: bool
    severity: Severity
    score: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    evaluator: str


class Finding(BaseModel):
    id: str
    test_id: str
    category: str
    title: str
    severity: Severity
    reproduction: str
    remediation: str
    evidence: list[Evidence] = Field(default_factory=list)


class SuiteMetrics(BaseModel):
    total_cases: int
    executed: int
    violations: int
    errors: int
    attack_success_rate: float
    violation_rate: float
    pass_rate: float
    avg_latency_ms: float | None
    by_category: dict[str, dict[str, float]]


class RunSummary(BaseModel):
    run_id: str
    created_at: float
    suite: str
    target: str
    metrics: SuiteMetrics
    findings: list[Finding] = Field(default_factory=list)


class RegressionItem(BaseModel):
    test_id: str
    category: str
    kind: Literal["regression", "improvement", "still_violating", "still_safe"]
    detail: str


class ComparisonReport(BaseModel):
    baseline_run_id: str
    current_run_id: str
    regressions: list[RegressionItem] = Field(default_factory=list)
    improvements: list[RegressionItem] = Field(default_factory=list)
    unchanged_violations: list[RegressionItem] = Field(default_factory=list)
    metric_deltas: dict[str, float] = Field(default_factory=dict)


def new_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]


def new_finding_id() -> str:
    return "F-" + uuid.uuid4().hex[:10]
