"""Practice agents server: three agents behind three different API shapes.

  POST /shop/chat                      {"messages": [...]}            -> {"reply", "tool_calls"}
  POST /hr/ask                         {"message", "history": [...]}  -> {"response", "tool_calls"}
  POST /ops/v1/chat/completions        OpenAI chat format             -> {"choices": [...]}
  GET  /healthz

Run locally:   uvicorn target_agents.app:app --port 9000
Settings:      TARGETS_LLM_BASE_URL / TARGETS_LLM_API_KEY (default: local Ollama),
               SHOP_MODEL, HR_MODEL, OPS_MODEL (model name per agent),
               TARGETS_ACCESS_TOKEN (if set, every request needs "Authorization: Bearer <token>").
Requests per minute are capped so a hosted copy cannot burn through an API quota.
"""

from __future__ import annotations

import os
import secrets
import time
from collections import deque
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from target_agents.agents import build_agents, run_agent

app = FastAPI(
    title="Practice agents", description="Agents to practise red-team scans on. Tools are simulated."
)
AGENTS = build_agents()
_CALLS: deque[float] = deque()
MAX_PER_MINUTE = int(os.getenv("TARGETS_MAX_PER_MINUTE", "60"))


class Msg(BaseModel):
    role: str = "user"
    content: str = Field(max_length=8000)


class MessagesBody(BaseModel):
    messages: list[Msg] = Field(min_length=1, max_length=40)


class MessageBody(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    history: list[Msg] = Field(default_factory=list, max_length=40)


class OpenAIBody(BaseModel):
    model: str | None = None
    messages: list[Msg] = Field(min_length=1, max_length=40)


def _guard(authorization: str | None) -> None:
    token = os.getenv("TARGETS_ACCESS_TOKEN")
    if token and not secrets.compare_digest(authorization or "", f"Bearer {token}"):
        raise HTTPException(status_code=401, detail="missing or wrong access token")
    now = time.time()
    while _CALLS and now - _CALLS[0] > 60:
        _CALLS.popleft()
    if len(_CALLS) >= MAX_PER_MINUTE:
        raise HTTPException(status_code=429, detail="too many requests, slow down")
    _CALLS.append(now)


def _answer(slug: str, history: list[dict[str, str]]) -> tuple[str, list[dict[str, Any]]]:
    try:
        return run_agent(AGENTS[slug], history)
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"model call failed: {exc.__class__.__name__}") from None


@app.post("/shop/chat")
def shop(body: MessagesBody, authorization: str | None = Header(default=None)) -> dict:
    _guard(authorization)
    reply, calls = _answer("shop", [m.model_dump() for m in body.messages])
    return {"reply": reply, "tool_calls": calls}


@app.post("/hr/ask")
def hr(body: MessageBody, authorization: str | None = Header(default=None)) -> dict:
    _guard(authorization)
    history = [m.model_dump() for m in body.history] + [{"role": "user", "content": body.message}]
    reply, calls = _answer("hr", history)
    return {"response": reply, "tool_calls": calls}


@app.post("/ops/v1/chat/completions")
def ops(body: OpenAIBody, authorization: str | None = Header(default=None)) -> dict:
    _guard(authorization)
    reply, calls = _answer("ops", [m.model_dump() for m in body.messages])
    return {
        "object": "chat.completion",
        "model": AGENTS["ops"].model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": reply,
                    "tool_calls": [
                        {"type": "function", "function": {"name": c["name"], "arguments": c["arguments"]}}
                        for c in calls
                    ],
                },
            }
        ],
    }


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "agents": len(AGENTS)}
