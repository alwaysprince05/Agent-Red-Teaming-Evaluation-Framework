"""Application entrypoint.

Starts the red-teaming REST API with uvicorn. Configuration is taken from
environment variables so the same code runs in development and production:

    AGENT_REDTEAM_HOST     bind address           (default 127.0.0.1)
    AGENT_REDTEAM_PORT     bind port              (default 8000)
    AGENT_REDTEAM_WORKERS  number of workers      (default 1)

Examples:

    python app.py                       # development
    AGENT_REDTEAM_HOST=0.0.0.0 AGENT_REDTEAM_PORT=8000 python app.py

The API refuses external agent targets unless a request explicitly sets
allow_external_targets plus an allowed_hosts entry (see docs/RESPONSIBLE_USE.md).
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("AGENT_REDTEAM_HOST", "127.0.0.1")
    port = int(os.getenv("AGENT_REDTEAM_PORT", "8000"))
    workers = int(os.getenv("AGENT_REDTEAM_WORKERS", "1"))

    uvicorn.run(
        "agent_redteam.api.main:app",
        host=host,
        port=port,
        workers=workers,
        # reload is a development aid; it must not run with multiple workers.
        reload=bool(os.getenv("AGENT_REDTEAM_RELOAD")) and workers == 1,
    )


if __name__ == "__main__":
    main()
