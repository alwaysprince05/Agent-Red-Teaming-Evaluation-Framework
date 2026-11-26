"""Model pool: the language models that attack and judge during an autonomous scan.

The scan never relies on one model. Attacker and judge models are listed in the
environment, each as "provider:model", and the scan rotates through them:

  AGENT_REDTEAM_ATTACKER_MODELS="ollama:qwen2.5:3b,groq:llama-3.1-8b-instant"
  AGENT_REDTEAM_JUDGE_MODELS="ollama:llama3.2:3b,groq:gemma2-9b-it"

Providers (all speak the OpenAI chat-completions API):
  ollama      local, http://127.0.0.1:11434/v1 (override with OLLAMA_BASE_URL), no key
  groq        https://api.groq.com/openai/v1, key from GROQ_API_KEY
  openrouter  https://openrouter.ai/api/v1, key from OPENROUTER_API_KEY
  openai      https://api.openai.com/v1, key from OPENAI_API_KEY
  custom      AGENT_REDTEAM_LLM_BASE_URL with AGENT_REDTEAM_LLM_API_KEY

When neither list is set, the older single-model settings
(AGENT_REDTEAM_LLM_BASE_URL + AGENT_REDTEAM_LLM_MODEL) are used for both roles.
Keys are only read from the environment and are never written to artifacts.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass

import httpx

ENV_ATTACKERS = "AGENT_REDTEAM_ATTACKER_MODELS"
ENV_JUDGES = "AGENT_REDTEAM_JUDGE_MODELS"

_PROVIDERS: dict[str, tuple[str, str | None]] = {
    # provider: (default base URL or env var holding it, env var holding the key)
    "ollama": ("http://127.0.0.1:11434/v1", None),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "custom": ("", "AGENT_REDTEAM_LLM_API_KEY"),
}
MAX_MODELS_PER_ROLE = 5
MAX_RETRIES = 3
MAX_RETRY_WAIT_S = 20.0


class ModelError(RuntimeError):
    """A model call failed or the model list is invalid."""


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"

    def base_url(self) -> str:
        if self.provider == "ollama":
            return os.getenv("OLLAMA_BASE_URL", _PROVIDERS["ollama"][0]).rstrip("/")
        if self.provider == "custom":
            return os.getenv("AGENT_REDTEAM_LLM_BASE_URL", "").rstrip("/")
        return _PROVIDERS[self.provider][0]

    def api_key(self) -> str | None:
        env = _PROVIDERS[self.provider][1]
        return os.getenv(env) if env else None

    def usable(self) -> bool:
        if not self.base_url():
            return False
        env = _PROVIDERS[self.provider][1]
        # Hosted providers need a key; local and custom endpoints may not.
        return self.provider in ("ollama", "custom") or bool(env and os.getenv(env))


def parse_model(text: str) -> ModelSpec:
    provider, sep, model = text.strip().partition(":")
    if not sep or not model:
        raise ModelError(f"model {text!r} must look like provider:model, e.g. groq:llama-3.1-8b-instant")
    provider = provider.lower()
    if provider not in _PROVIDERS:
        raise ModelError(f"unknown provider {provider!r}; use one of {', '.join(_PROVIDERS)}")
    return ModelSpec(provider, model.strip())


def parse_model_list(text: str) -> list[ModelSpec]:
    specs: list[ModelSpec] = []
    for item in text.split(","):
        if item.strip():
            spec = parse_model(item)
            if spec not in specs:
                specs.append(spec)
    return specs[:MAX_MODELS_PER_ROLE]


def _legacy_single() -> list[ModelSpec]:
    if os.getenv("AGENT_REDTEAM_LLM_BASE_URL") and os.getenv("AGENT_REDTEAM_LLM_MODEL"):
        return [ModelSpec("custom", os.environ["AGENT_REDTEAM_LLM_MODEL"])]
    return []


def models_for(role: str) -> list[ModelSpec]:
    """Usable models for 'attacker' or 'judge'. Judges default to the attacker list."""
    if role not in ("attacker", "judge"):
        raise ValueError(f"unknown role {role!r}")
    raw = os.getenv(ENV_ATTACKERS if role == "attacker" else ENV_JUDGES, "")
    if not raw and role == "judge":
        raw = os.getenv(ENV_ATTACKERS, "")
    specs = parse_model_list(raw) if raw else _legacy_single()
    return [s for s in specs if s.usable()]


def chat(
    spec: ModelSpec,
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.7,
    timeout_s: float = 90.0,
    max_tokens: int = 1200,
) -> str:
    """One chat-completions call. Raises ModelError on any failure."""
    headers = {"Content-Type": "application/json"}
    key = spec.api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    payload = {
        "model": spec.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = httpx.post(
                spec.base_url() + "/chat/completions", json=payload, headers=headers, timeout=timeout_s
            )
        except httpx.HTTPError as exc:
            raise ModelError(f"{spec.label} unreachable: {exc.__class__.__name__}") from None
        if resp.status_code in (429, 500, 502, 503) and attempt < MAX_RETRIES:
            # Rate limited or briefly down: wait as the provider asks, then try again.
            time.sleep(_retry_delay(resp, attempt))
            continue
        if resp.status_code >= 400:
            raise ModelError(f"{spec.label} returned HTTP {resp.status_code}")
        try:
            content = resp.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError):
            raise ModelError(f"{spec.label} sent an unexpected response") from None
        return _strip_thinking(str(content or ""))
    raise ModelError(f"{spec.label} kept failing")  # pragma: no cover


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    try:
        wait = float(resp.headers.get("retry-after", ""))
    except ValueError:
        wait = 2.0 * (attempt + 1)
    return max(0.5, min(wait, MAX_RETRY_WAIT_S))


def _strip_thinking(text: str) -> str:
    """Drop <think>...</think> reasoning that some models print before the answer."""
    return re.sub(r"<think>.*?(</think>|$)", "", text, flags=re.S).strip()



def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model reply (code fences and chatter allowed)."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end <= start:
            raise ModelError("model reply contains no JSON object") from None
        try:
            data = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            raise ModelError("model reply is not valid JSON") from None
    if not isinstance(data, dict):
        raise ModelError("model reply is not a JSON object")
    return data
