"""Adapters Package — Connects the framework to different AI agent targets.

This package provides the "adapters" that let the framework talk to AI agents.
An adapter takes attack prompts, sends them to the agent, and captures the response.

Available adapters:
  - MockAgent: Built-in fake agents for safe offline testing (mock:weak / mock:strong).
  - HTTPAgentAdapter: Sends attacks to a real AI agent over HTTP (only if authorized).

Key exports:
  - AgentAdapter: The base class all adapters must follow.
  - resolve_target: Picks the right adapter based on a target string like "mock:weak" or a URL.
  - TargetNotAuthorizedError: Raised when someone tries to test an agent they haven't authorized.
  - MOCK_TARGETS: List of safe built-in targets ("mock:weak", "mock:strong").
"""

from agent_redteam.adapters.base import (
    MOCK_TARGETS,
    AgentAdapter,
    TargetNotAuthorizedError,
    resolve_target,
)

__all__ = [
    "MOCK_TARGETS",
    "AgentAdapter",
    "TargetNotAuthorizedError",
    "resolve_target",
]
