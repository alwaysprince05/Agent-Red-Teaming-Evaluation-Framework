"""Practice agents: API shapes, access token and rate cap. The model call is faked."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

import target_agents.app as targets
from agent_redteam.adapters.http_agent import HTTPAgentAdapter
from agent_redteam.core.schemas import Turn
from target_agents.agents import build_agents


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        targets, "run_agent", lambda spec, history: (f"{spec.slug}: {history[-1]['content']}", [])
    )
    targets._CALLS.clear()
    monkeypatch.delenv("TARGETS_ACCESS_TOKEN", raising=False)
    return TestClient(targets.app)


def test_three_api_shapes(client):
    r = client.post("/shop/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.json() == {"reply": "shop: hi", "tool_calls": []}
    r = client.post("/hr/ask", json={"message": "hello", "history": []})
    assert r.json()["response"] == "hr: hello"
    r = client.post("/ops/v1/chat/completions", json={"messages": [{"role": "user", "content": "yo"}]})
    assert r.json()["choices"][0]["message"]["content"] == "ops: yo"


def test_access_token(client, monkeypatch):
    monkeypatch.setenv("TARGETS_ACCESS_TOKEN", "t0ken")
    assert client.post("/hr/ask", json={"message": "x"}).status_code == 401
    ok = client.post("/hr/ask", json={"message": "x"}, headers={"Authorization": "Bearer t0ken"})
    assert ok.status_code == 200


def test_rate_cap(client, monkeypatch):
    monkeypatch.setattr(targets, "MAX_PER_MINUTE", 2)
    for _ in range(2):
        assert client.post("/hr/ask", json={"message": "x"}).status_code == 200
    assert client.post("/hr/ask", json={"message": "x"}).status_code == 429


def test_secrets_are_fresh_canaries():
    a, b = build_agents(), build_agents()
    found = re.findall(r"CANARY-[A-Z0-9]{10}", a["shop"].prompt)
    assert len(found) == 2 and found[0] not in b["shop"].prompt


def test_scanner_adapter_detects_each_shape(client, monkeypatch):
    import httpx

    def post(url, json=None, headers=None, timeout=None, follow_redirects=None):
        return client.post(url.replace("http://agents", ""), json=json, headers=headers)

    monkeypatch.setattr(httpx, "post", post)
    for path, fmt in (
        ("/shop/chat", "messages"),
        ("/hr/ask", "message"),
        ("/ops/v1/chat/completions", "openai"),
    ):
        ad = HTTPAgentAdapter("http://agents" + path)
        r = ad.send([Turn(content="ping")])
        assert r.error is None and r.text.endswith("ping"), (path, r)
        assert ad.request_format == fmt


def test_model_call_retries_rate_limit(monkeypatch):
    import httpx

    import target_agents.agents as agents

    replies = [
        httpx.Response(429, headers={"retry-after": "0"}, json={}, request=httpx.Request("POST", "http://m")),
        httpx.Response(
            200,
            json={"choices": [{"message": {"content": "<think>x</think>Hello"}}]},
            request=httpx.Request("POST", "http://m"),
        ),
    ]
    monkeypatch.setattr(httpx, "post", lambda *a, **k: replies.pop(0))
    monkeypatch.setattr(agents.time, "sleep", lambda s: None)
    reply, calls = agents.run_agent(build_agents()["hr"], [{"role": "user", "content": "hi"}])
    assert reply == "Hello" and calls == []
