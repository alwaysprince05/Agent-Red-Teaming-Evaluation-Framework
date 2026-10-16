"""HTTP Agent Adapter — Sends attack prompts to a real AI agent over the network.

This file lets the framework test a real AI agent that runs on a web server.
It sends conversation messages via HTTP POST and reads back the agent's reply.

How it works:
  1. Takes the attack prompt (a list of conversation turns).
  2. Sends it as a JSON POST request to the agent's URL.
  3. Reads the agent's response (text + any tool calls it made).
  4. Returns the response so the evaluator can check if the agent was safe.

Error handling:
  - If the agent takes too long, it returns a timeout error.
  - If the HTTP request fails, it returns an HTTP error.
  - If the response is not valid JSON, it returns a parse error.
  - Errors are never hidden — they are always recorded.

Expected API format from the target agent:
  POST <url>   {"messages": [{"role": "user", "content": "..."}, ...]}
  -> 200 {"text": "...", "tool_calls": [{"name": ..., "arguments": {...}}]}
"""

from __future__ import annotations

import time

import httpx

from agent_redteam.adapters.base import AgentAdapter
from agent_redteam.core.schemas import AgentResponse, ToolCall, Turn


class HTTPAgentAdapter(AgentAdapter):
    name = "http"

    def __init__(
        self,
        url: str,
        *,
        timeout_s: float = 15.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url = url
        self.timeout_s = timeout_s
        self.headers = dict(headers or {})

    def send(self, turns: list[Turn]) -> AgentResponse:
        start = time.time()
        payload = {
            "messages": [{"role": t.role, "content": t.content} for t in turns],
        }
        try:
            resp = httpx.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout_s,
            )
            resp.raise_for_status()
            body = resp.json()
        except httpx.TimeoutException:
            return AgentResponse(error=f"timeout after {self.timeout_s}s", latency_ms=self.timeout_s * 1000)
        except httpx.HTTPError as exc:
            return AgentResponse(error=f"http error: {exc}")
        except ValueError as exc:
            return AgentResponse(error=f"invalid JSON from target: {exc}")

        text = body.get("text") or ""
        tool_calls = [
            ToolCall(name=str(tc.get("name", "")), arguments=tc.get("arguments") or {})
            for tc in body.get("tool_calls") or []
            if isinstance(tc, dict)
        ]
        return AgentResponse(
            text=text,
            tool_calls=tool_calls,
            latency_ms=round((time.time() - start) * 1000, 3),
        )
