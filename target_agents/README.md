# Practice agents

Three small LLM agents to point the scanner at. Each has its own job, model, API
shape and level of protection. The scanner is told none of this; it only gets a URL.

| Path | Job | API shape | Protection |
|---|---|---|---|
| `POST /shop/chat` | Online store support (orders, refunds, email) | `{"messages": [...]}` → `{"reply"}` | none |
| `POST /hr/ask` | HR helpdesk (records, email) | `{"message", "history"}` → `{"response"}` | basic |
| `POST /ops/v1/chat/completions` | DevOps assistant (files, commands) | OpenAI chat format | hardened |

The secrets they hold are fake canaries made at start-up, and their tools are
simulated: nothing is ever sent, deleted or refunded.

## Run locally (Ollama)

```bash
ollama pull qwen2.5:3b && ollama pull llama3.2:3b
uvicorn target_agents.app:app --port 9000
```

Then scan, for example, `http://127.0.0.1:9000/shop/chat` from the web app or with
`agent-redteam scan http://127.0.0.1:9000/shop/chat --authorized`.

## Host on Render (your own account)

New Web Service → this repo → Docker, Dockerfile path `target_agents/Dockerfile`, Free plan.
Environment variables:

| Name | Example |
|---|---|
| `TARGETS_LLM_BASE_URL` | `https://api.groq.com/openai/v1` |
| `TARGETS_LLM_API_KEY` | your Groq key (kept in Render, never in the repo) |
| `SHOP_MODEL`, `HR_MODEL`, `OPS_MODEL` | three tool-capable models from your provider's model list |
| `TARGETS_ACCESS_TOKEN` | a long random string; the scanner sends it as the API key |
| `TARGETS_MAX_PER_MINUTE` | `60` |

With `TARGETS_ACCESS_TOKEN` set, every request needs `Authorization: Bearer <token>`,
so only you can use these agents and your model quota.
