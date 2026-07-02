#!/bin/bash

# Aegis Automated Setup Script
set -e

echo "🛡️  Starting Aegis setup..."

# 1. Create virtual environment
if [ ! -d "venv" ]; then
    echo "[1/4] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[1/4] Virtual environment already exists."
fi

# 2. Install dependencies
echo "[2/4] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Initialize database
echo "[3/4] Initializing database..."
python scripts/seed_db.py

# 3.5. Ensure Redis and RQ Worker are active
echo "[3.5/4] Ensuring Redis and RQ Worker are running..."

# Check if Redis is running on 6379
REDIS_RUNNING=0
if nc -z 127.0.0.1 6379 2>/dev/null; then
    REDIS_RUNNING=1
elif command -v lsof >/dev/null && lsof -i :6379 >/dev/null; then
    REDIS_RUNNING=1
fi

if [ $REDIS_RUNNING -eq 0 ]; then
    echo "⚠️  Redis not detected on localhost:6379."
    if command -v docker >/dev/null; then
        echo "🐳  Docker detected. Spawning redis container..."
        docker rm -f aegis-redis 2>/dev/null || true
        docker run -d \
            -p 127.0.0.1:6379:6379 \
            --read-only \
            --cap-drop ALL \
            --security-opt no-new-privileges \
            --tmpfs /tmp:size=64m,mode=1777 \
            -v aegis-redis-data:/data \
            --name aegis-redis \
            redis:7.4.9-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99
        echo "Waiting for Redis to start..."
        sleep 2
        REDIS_RUNNING=1
    else
        echo "⚠️  Redis server and Docker are missing. Running in-process simulated mode."
    fi
else
    echo "✅  Redis is running on port 6379."
fi

# Terminate any old workers to ensure fresh code reload
echo "Stopping old RQ worker processes..."
pkill -f "rq worker" || true

if [ $REDIS_RUNNING -eq 1 ]; then
    # Start RQ worker in the background
    echo "Starting RQ background worker..."
    mkdir -p scans
    nohup venv/bin/rq worker --url redis://localhost:6379 > scans/worker.log 2>&1 &
else
    echo "Skipping RQ background worker (running in-process simulated mode)."
fi

# 4. Run the application
echo "[4/4] Setup complete! Starting Aegis..."
echo "Access the dashboard at http://127.0.0.1:5001"
exec venv/bin/uvicorn app.main:app --host "${AEGIS_HOST:-127.0.0.1}" --port 5001 --reload
