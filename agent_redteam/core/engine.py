"""Execution engine: runs test cases against a target with safety controls.

Safety controls implemented here:
  - per-case wall-clock timeout (thread-based, daemonized);
  - global rate limit between consecutive sends;
  - per-case isolation (each case gets a fresh conversation and record).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from agent_redteam.adapters.base import AgentAdapter
from agent_redteam.core.schemas import (
    AgentResponse,
    ExecStatus,
    ExecutionRecord,
    TestCase,
    new_run_id,
)


@dataclass
class EngineConfig:
    timeout_s: float = 15.0
    rate_limit_s: float = 0.2  # min seconds between consecutive sends
    max_turns: int = 20


@dataclass
class EngineStats:
    sent: int = 0
    timeouts: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0
    rate_limit_waits_s: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


def _call_with_timeout(adapter: AgentAdapter, turns: list, timeout_s: float) -> AgentResponse:
    result: dict = {}

    def target() -> None:
        try:
            result["response"] = adapter.send(turns)
        except Exception as exc:  # adapter crashed
            result["error"] = f"adapter raised: {exc.__class__.__name__}: {exc}"

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        return AgentResponse(error=f"target timed out after {timeout_s}s")
    if "error" in result:
        return AgentResponse(error=result["error"])
    return result["response"]


class ExecutionEngine:
    """Executes test cases against one adapter, capturing execution records."""

    def __init__(self, adapter: AgentAdapter, config: EngineConfig | None = None) -> None:
        self.adapter = adapter
        self.config = config or EngineConfig()
        self.stats = EngineStats()
        self._last_send: float | None = None

    def _respect_rate_limit(self) -> None:
        if self._last_send is None:
            return
        wait = self.config.rate_limit_s - (time.time() - self._last_send)
        if wait > 0:
            self.stats.rate_limit_waits_s += wait
            time.sleep(wait)

    def run_case(self, run_id: str, case: TestCase) -> ExecutionRecord:
        record = ExecutionRecord(
            run_id=run_id,
            test_id=case.id,
            category=case.category.value,
            started_at=time.time(),
        )
        # Per-case isolation: the case owns a fresh, validated conversation.
        turns = case.turns[: self.config.max_turns]
        record.turns_sent = turns

        self._respect_rate_limit()
        self._last_send = time.time()

        response = _call_with_timeout(self.adapter, turns, self.config.timeout_s)
        record.finish(response)
        record.mark(ExecStatus.ok if response.error is None else ExecStatus.timeout)

        with self.stats._lock:
            self.stats.sent += 1
            if response.error:
                if record.status is ExecStatus.timeout:
                    self.stats.timeouts += 1
                else:
                    record.status = ExecStatus.error
                    self.stats.errors += 1
            if response.latency_ms is not None:
                self.stats.total_latency_ms += response.latency_ms
        return record


def new_engine_run_id() -> str:
    return new_run_id()
