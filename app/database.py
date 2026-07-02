import os
import sqlite3
import threading
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import redis

BASE_DIR = Path(__file__).resolve().parent
local_root = BASE_DIR.parent
PROJECT_ROOT = local_root

if os.environ.get("VERCEL"):
    DB_PATH = Path("/tmp/aegis_demo.db")
    DOWNLOAD_DIR = Path("/tmp/downloads")
    SCANS_DIR = Path("/tmp/scans")
else:
    data_dir = os.environ.get("AEGIS_DATA_DIR")
    if data_dir:
        data_root = Path(data_dir).expanduser().resolve()
        DB_PATH = data_root / "aegis_demo.db"
        DOWNLOAD_DIR = data_root / "downloads"
        SCANS_DIR = data_root / "scans"
    else:
        try:
            test_file = local_root / ".test_write"
            test_file.touch()
            test_file.unlink()

            DB_PATH = BASE_DIR / "aegis_demo.db"
            DOWNLOAD_DIR = BASE_DIR / "downloads"
            SCANS_DIR = local_root / "scans"
        except (IOError, OSError):
            user_root = Path.home() / ".aegis"
            user_root.mkdir(parents=True, exist_ok=True)

            DB_PATH = user_root / "aegis_demo.db"
            DOWNLOAD_DIR = user_root / "downloads"
            SCANS_DIR = user_root / "scans"


DATABASE_URL = os.environ.get("DATABASE_URL", "")
USING_POSTGRES = DATABASE_URL.startswith(("postgresql://", "postgres://"))


class PostgresConnection:
    """Small DB-API adapter so application SQL can remain portable."""

    def __init__(self, connection):
        self._connection = connection

    @staticmethod
    def _sql(statement: str) -> str:
        return statement.replace("?", "%s")

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()):
        return self._connection.execute(self._sql(statement), parameters)

    def executemany(self, statement: str, parameters):
        return self._connection.executemany(self._sql(statement), parameters)

    def cursor(self):
        return PostgresCursor(self._connection.cursor())

    def commit(self):
        return self._connection.commit()

    def rollback(self):
        return self._connection.rollback()

    def close(self):
        return self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


class PostgresCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()):
        self._cursor.execute(statement.replace("?", "%s"), parameters)
        return self

    def executemany(self, statement: str, parameters):
        self._cursor.executemany(statement.replace("?", "%s"), parameters)
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


def get_connection():
    if USING_POSTGRES:
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("PostgreSQL requires psycopg. Install production dependencies.") from exc
        return PostgresConnection(psycopg.connect(DATABASE_URL))
    return sqlite3.connect(DB_PATH)


DEFAULT_USERS = [
    ("admin", "administrator", "ADMIN-API-KEY-12345"),
    ("devuser", "developer", "DEV-API-KEY-67890"),
    ("guest", "guest", "GUEST-API-KEY-00000"),
]

DEFAULT_WAF_RULES = [
    ("' OR '", "SQL Injection (OR operator bypass)", 1),
    ("1=1", "SQL Injection (tautology bypass)", 1),
    ("--", "SQL comment character block", 1),
    ("cat /etc/passwd", "LFI/Command execution pattern 1", 1),
    ("\\.\\./", "Directory Traversal pattern (../)", 1),
    ("pickle\\.loads", "Python deserialization hijack detector", 1),
    ("eval\\(", "Python dynamic expression injection detector", 1),
    ("__import__|system\\(|subprocess", "Python code execution attempt", 1),
    ("<\\s*script", "XSS (Dangerous script tags)", 1),
    ("on\\w+\\s*=", "XSS (HTML event handler hijacking)", 1),
    ("javascript\\s*:", "XSS (Javascript URI prefix)", 1),
    ("169\\.254\\.169\\.254", "SSRF (Cloud metadata server IP)", 1),
    ("localhost|127\\.0\\.0\\.1", "SSRF (Localhost lookup blocker)", 1),
]


def initialize_database(*, reset: bool = False):
    if not USING_POSTGRES:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    user_id = "BIGSERIAL PRIMARY KEY" if USING_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id {user_id},
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT NOT NULL
        )
    """)

    if reset:
        cursor.execute("DELETE FROM users")
    if cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, role, api_key) VALUES (?, ?, ?)",
            DEFAULT_USERS,
        )

    waf_id = "BIGSERIAL PRIMARY KEY" if USING_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS waf_rules (
            id {waf_id},
            pattern TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    """)

    if reset:
        cursor.execute("DELETE FROM waf_rules")
    if cursor.execute("SELECT COUNT(*) FROM waf_rules").fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
            DEFAULT_WAF_RULES,
        )

    auth_id = "BIGSERIAL PRIMARY KEY" if USING_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS auth_users (
            id {auth_id},
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id {auth_id},
            user_id BIGINT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS application_state (
            state_key TEXT PRIMARY KEY,
            state_value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS projects (
            id {auth_id},
            name TEXT NOT NULL,
            repository_url TEXT,
            github_full_name TEXT,
            default_branch TEXT NOT NULL DEFAULT 'main',
            scan_preset TEXT NOT NULL DEFAULT 'standard',
            created_by BIGINT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_members (
            project_id BIGINT NOT NULL,
            user_id BIGINT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (project_id, user_id)
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id {auth_id},
            job_id TEXT NOT NULL UNIQUE,
            project_id BIGINT NOT NULL,
            requested_by BIGINT NOT NULL,
            target TEXT NOT NULL,
            preset TEXT NOT NULL,
            state TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            result_json TEXT,
            new_findings INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_connections (
            user_id BIGINT PRIMARY KEY,
            github_login TEXT NOT NULL,
            token_encrypted TEXT NOT NULL,
            scopes TEXT NOT NULL,
            connected_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_oauth_states (
            state_hash TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL,
            verifier_encrypted TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS notification_channels (
            id {auth_id},
            project_id BIGINT NOT NULL,
            name TEXT NOT NULL,
            channel_type TEXT NOT NULL,
            config_encrypted TEXT NOT NULL,
            events TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by BIGINT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS notification_deliveries (
            id {auth_id},
            channel_id BIGINT NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS audit_events (
            id {auth_id},
            actor_id BIGINT,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def get_application_state(key: str, default=None):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT state_value FROM application_state WHERE state_key = ?", (key,)
        ).fetchone()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return default


def set_application_state(key: str, value) -> None:
    encoded = json.dumps(value, separators=(",", ":"))
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        updated = connection.execute(
            "UPDATE application_state SET state_value = ?, updated_at = ? WHERE state_key = ?",
            (encoded, now, key),
        )
        rowcount = getattr(updated, "rowcount", 0)
        if not rowcount:
            connection.execute(
                """INSERT INTO application_state (state_key, state_value, updated_at)
                   VALUES (?, ?, ?)""",
                (key, encoded, now),
            )

class InMemoryRedis:
    def __init__(self):
        self.storage = {}
        self.lists = {}
        self.channels = {}
        self.lock = threading.Lock()

    def ping(self):
        return True

    def hset(self, name, key=None, value=None, mapping=None):
        with self.lock:
            if name not in self.storage:
                self.storage[name] = {}
            if mapping:
                for k, v in mapping.items():
                    self.storage[name][k] = str(v).encode() if not isinstance(v, bytes) else v
            else:
                self.storage[name][key] = str(value).encode() if not isinstance(value, bytes) else value
        return 1

    def hget(self, name, key):
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        with self.lock:
            val = self.storage.get(name, {}).get(key)
        if isinstance(val, str):
            return val.encode()
        return val

    def rpush(self, name, *values):
        with self.lock:
            if name not in self.lists:
                self.lists[name] = []
            for v in values:
                self.lists[name].append(v.encode() if isinstance(v, str) else v)
            return len(self.lists[name])

    def lrange(self, name, start, end):
        with self.lock:
            lst = self.lists.get(name, [])
            if end == -1:
                return lst[start:]
            return lst[start:end+1]

    def ltrim(self, name, start, end):
        with self.lock:
            values = self.lists.get(name, [])
            self.lists[name] = values[start:] if end == -1 else values[start:end + 1]
        return True

    def expire(self, name, seconds):
        return True

    def incr(self, name):
        with self.lock:
            current = int(self.storage.get(name, 0))
            self.storage[name] = current + 1
            return current + 1

    def ttl(self, name):
        return -1

    def publish(self, channel, message):
        with self.lock:
            if channel in self.channels:
                for q in self.channels[channel]:
                    q.append(message)
        return 1

    def pubsub(self):
        parent = self
        class PubSubMock:
            def __init__(self):
                self.channel = None
                self.queue = []

            def subscribe(self, channel):
                self.channel = channel
                with parent.lock:
                    if channel not in parent.channels:
                        parent.channels[channel] = []
                    parent.channels[channel].append(self.queue)

            def get_message(self, ignore_subscribe_messages=True, timeout=0.1):
                with parent.lock:
                    if self.queue:
                        msg = self.queue.pop(0)
                        return {"data": msg.encode('utf-8') if isinstance(msg, str) else msg}
                return None

            def unsubscribe(self, channel):
                with parent.lock:
                    if channel in parent.channels and self.queue in parent.channels[channel]:
                        parent.channels[channel].remove(self.queue)

            def close(self):
                if self.channel:
                    self.unsubscribe(self.channel)

        return PubSubMock()

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_URL = os.environ.get("REDIS_URL", f"redis://{REDIS_HOST}:6379/0")
try:
    _temp_client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=0.5)
    _temp_client.ping()
    redis_client = _temp_client
    REDIS_AVAILABLE = True
except Exception:
    redis_client = InMemoryRedis()
    REDIS_AVAILABLE = False
