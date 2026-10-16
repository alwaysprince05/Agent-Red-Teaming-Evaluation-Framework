"""Core Package — The brain of the red-teaming framework.

This package contains all the core logic:
  - schemas.py:    Data models (test cases, results, findings, metrics, etc.)
  - suite.py:      Loads and validates attack test suites from YAML/JSON files.
  - engine.py:     Runs individual test cases against an agent with safety controls.
  - runner.py:     Orchestrates a full evaluation run (load suite → execute → evaluate → report).
  - compare.py:    Compares two runs to find regressions and improvements.
  - generator.py:  Creates new attack test cases (via LLM or deterministic mutations).
  - adaptive.py:   Smart loop that plans, generates, attacks, and reflects automatically.
  - benchmark.py:  Measures throughput, latency, and failure rates.
"""


from agent_redteam.core.schemas import (
    AgentResponse,
    AttackCategory,
    ComparisonReport,
    EvaluationResult,
    EvaluationStatus,
    Evidence,
    ExecStatus,
    ExecutionRecord,
    Finding,
    Policy,
    RegressionItem,
    RunSummary,
    Severity,
    SuiteMetrics,
    TestCase,
    ToolCall,
    Turn,
    new_finding_id,
    new_run_id,
)

__all__ = [
    "AgentResponse",
    "AttackCategory",
    "ComparisonReport",
    "EvaluationResult",
    "EvaluationStatus",
    "Evidence",
    "ExecStatus",
    "ExecutionRecord",
    "Finding",
    "Policy",
    "RegressionItem",
    "RunSummary",
    "Severity",
    "SuiteMetrics",
    "TestCase",
    "ToolCall",
    "Turn",
    "new_finding_id",
    "new_run_id",
]
