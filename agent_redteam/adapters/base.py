"""Adapter Base — Defines how the framework talks to AI agents.

This file contains:
  1. AgentAdapter (base class): Every adapter must follow this pattern.
     It has one main method — send() — which sends conversation turns to the agent
     and gets back the agent's response.

  2. resolve_target(): Takes a target string (like "mock:weak" or "http://...") and
     returns the correct adapter to use. This is the single place that decides
     which adapter to create.

  3. Safety checks: External HTTP targets are blocked by default. You must
     explicitly allow them AND list the host in an allowlist. Localhost targets
     (127.0.0.1) are always allowed. This prevents accidentally testing
     someone else's agent.

  4. TargetNotAuthorizedError: Raised when a target is not allowed.
"""

from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from urllib.parse import urlsplit

from agent_redteam.core.schemas import AgentResponse, Turn

# Target spec for the built-in safe mock agents: "mock:weak" / "mock:strong"
MOCK_TARGETS = ("mock:weak", "mock:strong")
# Real model-driven agents (see adapters/llm_agent.py): "llm:weak" / "llm:strong"
LLM_TARGETS = ("llm:weak", "llm:strong")


class TargetNotAuthorizedError(ValueError):
    """Raised when a target is not explicitly authorized for testing."""


class AgentAdapter(ABC):
    """Normalizes communication with an agent target.

    Implementations must be read-only towards third parties: they only *send
    turns* to the configured target and capture what comes back. They must
    never execute tool calls themselves.
    """

    name: str = "adapter"

    @abstractmethod
    def send(self, turns: list[Turn]) -> AgentResponse:
        """Send the conversation to the target and return its (normalized) response."""


def _is_loopback_host(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(info[4][0]).is_loopback for info in infos)


# Hosts that are never tested, whatever the flags say: government, military,
# education and intergovernmental domains, including country forms like gov.in.
_PROTECTED_TLDS = {"gov", "mil", "edu", "int"}
_PROTECTED_SECOND_LEVEL = {"gov", "mil", "edu", "ac", "nic"}


def is_protected_host(host: str) -> bool:
    labels = [p for p in host.lower().rstrip(".").split(".") if p]
    if len(labels) < 2:
        return False
    if labels[-1] in _PROTECTED_TLDS:
        return True
    # e.g. india.gov.in, mod.gov.uk, iitb.ac.in; only when the last label is a country code
    return len(labels[-1]) == 2 and labels[-2] in _PROTECTED_SECOND_LEVEL


def validate_external_target(
    url: str,
    *,
    allow_external: bool,
    host_allowlist: list[str] | None,
) -> str:
    """Validate an HTTP(S) target before any request is made.

    Rules:
      - government / military / education / intergovernmental hosts are always refused;
      - loopback targets (localhost/127.0.0.1) are always allowed;
      - any external host requires allow_external=True AND the host to be in
        host_allowlist (if a non-empty allowlist is provided).
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise TargetNotAuthorizedError(f"unsupported scheme {parts.scheme!r} in target URL")
    host = parts.hostname or ""
    if not host:
        raise TargetNotAuthorizedError("target URL has no hostname")
    if is_protected_host(host):
        raise TargetNotAuthorizedError(
            f"refusing target {host!r}: government, military, education and intergovernmental "
            "domains are blocked by a built-in guardrail that cannot be turned off"
        )
    if _is_loopback_host(host):
        return url
    if not allow_external:
        raise TargetNotAuthorizedError(
            f"refusing external target {host!r}: not authorized. "
            "Only test agents you own or have written permission to test "
            "(set allow_external_targets=true and add the host to allowed_hosts)."
        )
    if host_allowlist and host not in host_allowlist:
        raise TargetNotAuthorizedError(
            f"host {host!r} is not in the authorized allowed_hosts list"
        )
    return url


def validate_public_target(url: str) -> str:
    """Stricter check for URLs typed into the public demo.

    Besides the protected-domain rule, every address the host resolves to must be a
    public internet address. Loopback, private (10.x, 192.168.x, ...), link-local
    (including cloud metadata at 169.254.169.254), carrier-grade NAT and reserved
    ranges are refused, so the hosted scanner cannot be pointed at its own network.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise TargetNotAuthorizedError("only http and https agent URLs can be scanned")
    if parts.username or parts.password:
        raise TargetNotAuthorizedError("put credentials in the API key field, not in the URL")
    host = parts.hostname or ""
    if not host:
        raise TargetNotAuthorizedError("target URL has no hostname")
    if is_protected_host(host):
        raise TargetNotAuthorizedError(
            f"refusing target {host!r}: government, military, education and intergovernmental "
            "domains are blocked by a built-in guardrail that cannot be turned off"
        )
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80))
    except (socket.gaierror, UnicodeError):
        raise TargetNotAuthorizedError(f"cannot resolve host {host!r}") from None
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global or address.is_multicast:
            raise TargetNotAuthorizedError(
                f"refusing {host!r}: it points to a private or internal address, "
                "which the public demo never scans"
            )
    return url


def resolve_target(
    spec: str,
    *,
    allow_external: bool = False,
    host_allowlist: list[str] | None = None,
    http_options: dict | None = None,
) -> AgentAdapter:
    """Resolve a target spec into an adapter.

    Built-in safe specs: "mock:weak", "mock:strong".
    Model-driven specs: "llm:weak", "llm:strong" (endpoint authorized like HTTP targets).
    Anything starting with http:// or https:// is treated as an HTTP agent.
    """
    if spec in MOCK_TARGETS:
        from agent_redteam.adapters.mock_agent import MockAgent

        return MockAgent(profile=spec.split(":", 1)[1])
    if spec in LLM_TARGETS:
        from agent_redteam.adapters.llm_agent import LLMAgent, LLMTargetConfig

        config = LLMTargetConfig.from_env()
        validate_external_target(
            config.base_url, allow_external=allow_external, host_allowlist=host_allowlist
        )
        return LLMAgent(profile=spec.split(":", 1)[1], config=config)
    if spec.startswith("http://") or spec.startswith("https://"):
        validate_external_target(spec, allow_external=allow_external, host_allowlist=host_allowlist)
        from agent_redteam.adapters.http_agent import HTTPAgentAdapter

        return HTTPAgentAdapter(url=spec, **(http_options or {}))
    raise ValueError(
        f"unknown target spec {spec!r}; use 'mock:weak', 'mock:strong', 'llm:weak', 'llm:strong' "
        "or an authorized http(s) URL"
    )
