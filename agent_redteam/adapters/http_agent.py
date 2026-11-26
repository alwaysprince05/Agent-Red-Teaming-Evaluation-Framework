"""HTTP Agent Adapter: sends attack conversations to an agent running behind a URL.

Agents on the web do not share one API, so the adapter supports the common shapes
and detects which one the target speaks on the first call:

  openai    POST {"model", "messages": [...]}       -> choices[0].message.content
            (picked when the URL ends with /chat/completions)
  messages  POST {"messages": [{"role","content"}]} -> a text field in the JSON reply
  message   POST {"message": "...", "history": [...]}
  input     POST {"input": "..."}
  prompt    POST {"prompt": "..."}
  query     POST {"query": "..."}

The reply text is read from the first matching field: text, reply, response,
output, answer, message, content, result, completion, or the OpenAI choices shape.
Plain-text replies are accepted too. Tool calls are read from "tool_calls" in either
the simple {"name","arguments"} form or the OpenAI {"function": {...}} form.

Errors are never hidden: timeouts, HTTP errors and unreadable replies come back as
AgentResponse.error so the run records them instead of counting them as safe.
Redirects are not followed, so a target cannot bounce the scanner somewhere else.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from agent_redteam.adapters.base import AgentAdapter
from agent_redteam.core.schemas import AgentResponse, ToolCall, Turn

FORMATS = ("openai", "messages", "message", "input", "prompt", "query")
_DETECT_ORDER = ("messages", "message", "input", "prompt", "query")
_TEXT_KEYS = (
    "text",
    "reply",
    "response",
    "output",
    "answer",
    "message",
    "content",
    "result",
    "completion",
    "output_text",
    "generated_text",
)
MAX_REPLY_CHARS = 20_000


def _text_from(value: Any, depth: int = 0) -> str | None:
    """Find the reply text in a JSON value of unknown shape."""
    if depth > 4:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            found = _text_from(item, depth + 1)
            if found:
                return found
        return None
    if not isinstance(value, dict):
        return None
    choices = value.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            msg = first.get("message") or {}
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]
            if isinstance(first.get("text"), str):
                return first["text"]
    for key in _TEXT_KEYS:
        if key in value:
            found = _text_from(value[key], depth + 1)
            if found is not None:
                return found
    for key in ("data", "result", "output"):
        if isinstance(value.get(key), (dict, list)):
            found = _text_from(value[key], depth + 1)
            if found is not None:
                return found
    return None


def _tool_calls_from(body: Any) -> list[ToolCall]:
    if not isinstance(body, dict):
        return []
    raw = body.get("tool_calls")
    if raw is None:
        choices = body.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            raw = (choices[0].get("message") or {}).get("tool_calls")
    calls: list[ToolCall] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else item
        args = fn.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"raw": args[:500]}
        if not isinstance(args, dict):
            args = {"value": args}
        calls.append(ToolCall(name=str(fn.get("name", ""))[:100], arguments=args))
    return calls


class HTTPAgentAdapter(AgentAdapter):
    name = "http"

    def __init__(
        self,
        url: str,
        *,
        timeout_s: float = 30.0,
        headers: dict[str, str] | None = None,
        api_key: str | None = None,
        request_format: str = "auto",
        model: str | None = None,
    ) -> None:
        if request_format != "auto" and request_format not in FORMATS:
            raise ValueError(f"unknown request format {request_format!r}; use auto or one of {FORMATS}")
        self.url = url
        self.timeout_s = timeout_s
        self.headers = dict(headers or {})
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
        self.model = model
        if request_format == "auto" and url.rstrip("/").endswith("/chat/completions"):
            request_format = "openai"
        self.request_format = request_format  # "auto" until detection succeeds

    def _payload(self, fmt: str, messages: list[dict[str, str]]) -> dict:
        last = messages[-1]["content"]
        if fmt == "openai":
            return {"model": self.model or "default", "messages": messages}
        if fmt == "messages":
            return {"messages": messages}
        if fmt == "message":
            return {"message": last, "history": messages[:-1]}
        return {fmt: last}

    def _post(self, fmt: str, messages: list[dict[str, str]]) -> tuple[AgentResponse | None, str | None]:
        """One request in one format. Returns (response, None) or (None, reason it failed)."""
        start = time.time()
        try:
            resp = httpx.post(
                self.url,
                json=self._payload(fmt, messages),
                headers=self.headers,
                timeout=self.timeout_s,
                follow_redirects=False,
            )
        except httpx.TimeoutException:
            return AgentResponse(
                error=f"timeout after {self.timeout_s}s", latency_ms=self.timeout_s * 1000
            ), None
        except httpx.HTTPError as exc:
            return AgentResponse(error=f"http error: {exc.__class__.__name__}"), None
        latency = round((time.time() - start) * 1000, 3)
        if resp.status_code in (400, 404, 405, 415, 422):
            return None, f"HTTP {resp.status_code}"
        if resp.status_code >= 300:
            return AgentResponse(error=f"target returned HTTP {resp.status_code}", latency_ms=latency), None
        try:
            body: Any = resp.json()
        except ValueError:
            body = resp.text
        text = _text_from(body)
        if text is None:
            return None, "reply has no recognisable text field"
        return AgentResponse(
            text=text[:MAX_REPLY_CHARS],
            tool_calls=_tool_calls_from(body),
            latency_ms=latency,
        ), None

    def send(self, turns: list[Turn]) -> AgentResponse:
        """Multi-turn attacks are played as a real conversation: one request per user
        turn, with the agent's earlier replies included as assistant messages."""
        messages = [{"role": "user" if t.role == "tool" else t.role, "content": t.content} for t in turns]
        if sum(1 for t in turns if t.role == "user") <= 1:
            return self._send_once(messages)
        convo: list[dict[str, str]] = []
        replies: list[str] = []
        calls: list[ToolCall] = []
        latency = 0.0
        response = AgentResponse()
        for message in messages:
            convo.append(message)
            if message["role"] != "user":
                continue
            response = self._send_once(convo)
            if response.error:
                return response
            latency += response.latency_ms or 0.0
            replies.append(response.text)
            calls.extend(response.tool_calls)
            convo.append({"role": "assistant", "content": response.text})
        transcript = "\n\n".join(f"[reply to turn {i}] {r}" for i, r in enumerate(replies, 1))
        return AgentResponse(
            text=transcript[:MAX_REPLY_CHARS],
            tool_calls=calls,
            latency_ms=round(latency, 3),
            last_reply=response.text,
            last_tool_calls=response.tool_calls,
        )

    def _send_once(self, messages: list[dict[str, str]]) -> AgentResponse:
        if self.request_format != "auto":
            response, reason = self._post(self.request_format, messages)
            return response or AgentResponse(
                error=f"target did not accept the {self.request_format} format ({reason})"
            )
        reasons = []
        for fmt in _DETECT_ORDER:
            response, reason = self._post(fmt, messages)
            if response is not None:
                if response.error is None:
                    self.request_format = fmt
                return response
            reasons.append(f"{fmt}: {reason}")
        return AgentResponse(
            error="could not talk to the target in any supported format (" + "; ".join(reasons) + ")"
        )
