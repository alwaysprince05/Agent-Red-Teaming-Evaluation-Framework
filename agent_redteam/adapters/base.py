"""Agent adapter interface and target resolution.

Safe by default: `resolve_target` only accepts built-in mock agents unless the
caller explicitly passes an allowlist of authorized external hosts.
"""

from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from urllib.parse import urlsplit

from agent_redteam.core.schemas import AgentResponse, Turn

# Target spec for the built-in safe mock agents: "mock:weak" / "mock:strong"
MOCK_TARGETS = ("mock:weak", "mock:strong")


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


def validate_external_target(
    url: str,
    *,
    allow_external: bool,
    host_allowlist: list[str] | None,
) -> str:
    """Validate an HTTP(S) target before any request is made.

    Rules:
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


def resolve_target(
    spec: str,
    *,
    allow_external: bool = False,
    host_allowlist: list[str] | None = None,
) -> AgentAdapter:
    """Resolve a target spec into an adapter.

    Built-in safe specs: "mock:weak", "mock:strong".
    Anything starting with http:// or https:// is treated as an HTTP agent.
    """
    if spec in MOCK_TARGETS:
        from agent_redteam.adapters.mock_agent import MockAgent

        return MockAgent(profile=spec.split(":", 1)[1])
    if spec.startswith("http://") or spec.startswith("https://"):
        validate_external_target(spec, allow_external=allow_external, host_allowlist=host_allowlist)
        from agent_redteam.adapters.http_agent import HTTPAgentAdapter

        return HTTPAgentAdapter(url=spec)
    raise ValueError(
        f"unknown target spec {spec!r}; use 'mock:weak', 'mock:strong' or an authorized http(s) URL"
    )
