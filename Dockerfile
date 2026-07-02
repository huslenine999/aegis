FROM python:3.11.15-slim-bookworm@sha256:721dc13fd1be0a771e54b72097634291d628d0007dee9da777e2ce676a9c998f

WORKDIR /app
ENV AEGIS_CORS_ORIGINS=http://127.0.0.1:5001,http://localhost:5001 \
    AEGIS_DATA_DIR=/data \
    AEGIS_ENABLE_DEMO_LAB=false \
    AEGIS_REQUIRE_REDIS=false \
    FORWARDED_ALLOW_IPS=127.0.0.1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app:/app/app \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install -r requirements.txt \
    && groupadd --system aegis \
    && useradd --system --gid aegis --create-home --home-dir /home/aegis aegis \
    && mkdir -p /data \
    && chown aegis:aegis /data

COPY --chown=aegis:aegis app ./app
COPY --chown=aegis:aegis rules ./rules
COPY --chown=aegis:aegis policy_engine.py aegis.yml ./
USER aegis

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5001/ready', timeout=3)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001"]
