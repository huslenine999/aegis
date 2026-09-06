FROM python:3.14.7-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f

WORKDIR /app
ENV AEGIS_DATA_DIR=/data \
    AEGIS_ENV=production \
    AEGIS_ENABLE_DEMO_LAB=false \
    AEGIS_HOST=0.0.0.0 \
    AEGIS_REQUIRE_AUTH=true \
    AEGIS_REQUIRE_REDIS=true \
    AEGIS_REQUIRE_WORKER=true \
    AEGIS_REQUIRE_NOTIFIER=true \
    FORWARDED_ALLOW_IPS=127.0.0.1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app:/app/app \
    PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && /usr/local/bin/python -m pip install --no-cache-dir "uv==0.11.25" \
    && UV_PROJECT_ENVIRONMENT=/app/.venv /usr/local/bin/uv sync --locked --no-dev --extra scanner --no-install-project \
    && /usr/local/bin/python -m pip uninstall -y uv \
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

ENTRYPOINT ["python", "-m", "app.preflight"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001"]
