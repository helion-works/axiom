FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# git: scans clone repositories; curl: container healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir ".[api,ai]"

# Non-root user; the scan engine clones into /tmp/axiom_scans
RUN useradd --create-home --uid 10001 axiom \
    && mkdir -p /tmp/axiom_scans \
    && chown -R axiom:axiom /tmp/axiom_scans /app
USER axiom

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
