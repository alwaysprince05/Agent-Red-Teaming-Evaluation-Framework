"""App Entry Point — Starts the web server for the red-teaming REST API.

This is the file you run to start the web server:
    python app.py

It launches the FastAPI application using uvicorn (a fast Python web server).
Once running, you can:
  - Open http://127.0.0.1:8000/docs for the interactive Swagger UI.
  - Send HTTP requests to start evaluation runs, check status, and get results.

Configuration (via environment variables):
    AGENT_REDTEAM_HOST     — What address to listen on (default: 127.0.0.1)
    AGENT_REDTEAM_PORT     — What port to use (default: 8000)
    AGENT_REDTEAM_WORKERS  — How many worker processes to run (default: 1)
    AGENT_REDTEAM_RELOAD   — Enable auto-reload for development (only with 1 worker)
Settings can also live in a local .env file (see .env.example); shell values win.

Examples:
    python app.py                                              # development
    AGENT_REDTEAM_HOST=0.0.0.0 AGENT_REDTEAM_PORT=8000 python app.py  # production

Safety: The API refuses external agent targets unless you explicitly allow them.
"""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn


def load_env_file(path: str | Path = ".env") -> None:
    """Read KEY=value lines from a local .env file into the environment.

    Values already set in the shell win. The file is git-ignored, so keys stay on this machine.
    """
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def main() -> None:
    load_env_file()
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
