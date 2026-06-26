import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

try:
    from .database import DB_PATH, DOWNLOAD_DIR
except ImportError:
    from database import DB_PATH, DOWNLOAD_DIR


router = APIRouter(tags=["demo-lab"])

DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "dev-password")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "DEV-AWS-ID")


@router.get("/user")
def get_user(name: str = "guest"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT id, username, role, api_key FROM users WHERE username = '{name}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return {
        "query": query,
        "results": rows,
    }


@router.get("/ping")
def ping_host(host: str = "127.0.0.1"):
    command = f"ping -c 1 {host}"
    output = subprocess.check_output(command, shell=True, text=True)
    return {
        "command": command,
        "output": output,
    }


@router.get("/calculate")
def calculate(expr: str = "1+1"):
    result = eval(expr)
    return {
        "expression": expr,
        "result": result,
    }


@router.post("/load-profile")
async def load_profile(request: Request):
    body = await request.json()
    encoded_profile = body.get("profile", "")
    raw_data = base64.b64decode(encoded_profile)
    profile = pickle.loads(raw_data)
    return {
        "loaded_profile": str(profile),
    }


@router.get("/download")
def download_file(file: str = "sample.txt"):
    target_file = DOWNLOAD_DIR / file
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return PlainTextResponse(target_file.read_text())


@router.get("/hash")
def weak_hash(value: str = "password123"):
    digest = hashlib.md5(value.encode()).hexdigest()
    return {
        "value": value,
        "md5": digest,
    }


@router.get("/xss", response_class=HTMLResponse)
def xss_demo(msg: str = "Welcome to Aegis console."):
    return f"<html><body><div id='xss-output'>{msg}</div></body></html>"


@router.get("/ssrf")
def ssrf_demo(url: str = "http://127.0.0.1:5001/health"):
    import urllib.request

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Aegis-Simulated-Scanner/2.0"},
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            content = response.read().decode("utf-8", errors="ignore")
            return {
                "url": url,
                "status": "success",
                "response": content[:1000],
            }
    except Exception as e:
        return {
            "url": url,
            "status": "error",
            "message": str(e),
        }


@router.get("/debug-info")
def debug_info():
    return {
        "database_password": DATABASE_PASSWORD,
        "aws_access_key": AWS_ACCESS_KEY_ID,
        "environment": dict(os.environ),
    }


if __name__ == "__main__":
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI(title="Aegis Vulnerable Demo Lab")
    app.include_router(router)

    @app.get("/health")
    def health():
        return {"status": "running", "service": "aegis-demo-lab"}

    Path(DOWNLOAD_DIR).mkdir(exist_ok=True, parents=True)
    uvicorn.run(app, host="0.0.0.0", port=5001)
