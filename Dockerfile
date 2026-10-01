FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY agent_redteam ./agent_redteam

RUN pip install --no-cache-dir .

RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Safe by default: the service refuses non-loopback agent targets unless
# explicitly allowed in the request (allow_external_targets + host allowlist).
CMD ["uvicorn", "agent_redteam.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
