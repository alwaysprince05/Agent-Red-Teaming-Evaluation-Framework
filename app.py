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

Examples:
    python app.py                                              # development
    AGENT_REDTEAM_HOST=0.0.0.0 AGENT_REDTEAM_PORT=8000 python app.py  # production

Safety: The API refuses external agent targets unless you explicitly allow them.
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
