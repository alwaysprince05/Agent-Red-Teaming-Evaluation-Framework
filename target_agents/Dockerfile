# Practice agents to scan (see target_agents/README.md). Build from the repo root:
#   docker build -f target_agents/Dockerfile -t practice-agents .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn>=0.29" "httpx>=0.27" "pydantic>=2.6"
COPY target_agents ./target_agents
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 9000
CMD ["sh", "-c", "exec uvicorn target_agents.app:app --host 0.0.0.0 --port ${PORT:-9000}"]
