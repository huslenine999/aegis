FROM python:3.11-slim-bookworm

WORKDIR /app
ENV AEGIS_ENABLE_DEMO_LAB=false
ENV AEGIS_CORS_ORIGINS=http://127.0.0.1:5001,http://localhost:5001

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY policy_engine.py .
COPY aegis.yml .

RUN python scripts/seed_db.py
RUN useradd --create-home --shell /bin/bash aegis \
    && chown -R aegis:aegis /app
USER aegis

EXPOSE 5001

CMD ["python", "app/main.py"]
