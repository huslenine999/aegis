import os
import sqlite3
import threading
import json
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import redis

BASE_DIR = Path(__file__).resolve().parent
local_root = BASE_DIR.parent
PROJECT_ROOT = local_root


def _database_path(root: Path) -> Path:
    current = root / "aegis.db"
    legacy = root / "aegis_demo.db"
    return legacy if legacy.exists() and not current.exists() else current


if os.environ.get("VERCEL"):
    DB_PATH = Path("/tmp/aegis.db")
    DOWNLOAD_DIR = Path("/tmp/downloads")
    SCANS_DIR = Path("/tmp/scans")
else:
    data_dir = os.environ.get("AEGIS_DATA_DIR")
    if data_dir:
        data_root = Path(data_dir).expanduser().resolve()
        DB_PATH = _database_path(data_root)
        DOWNLOAD_DIR = data_root / "downloads"
        SCANS_DIR = data_root / "scans"
    else:
        try:
            test_file = local_root / ".test_write"
            test_file.touch()
            test_file.unlink()

            DB_PATH = _database_path(BASE_DIR)
            DOWNLOAD_DIR = BASE_DIR / "downloads"
            SCANS_DIR = local_root / "scans"
        except (IOError, OSError):
            user_root = Path.home() / ".aegis"
            user_root.mkdir(parents=True, exist_ok=True)

            DB_PATH = _database_path(user_root)
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
    connection = sqlite3.connect(DB_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


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


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Any], None]


def _identity_id_type() -> str:
    return "BIGSERIAL PRIMARY KEY" if USING_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"


def _create_schema_migrations_table(cursor) -> None:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
    """)


def _applied_migration_versions(cursor) -> set[int]:
    _create_schema_migrations_table(cursor)
    rows = cursor.execute("SELECT version FROM schema_migrations").fetchall()
    return {int(row[0]) for row in rows}


def _record_migration(cursor, migration: Migration) -> None:
    cursor.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
        (migration.version, migration.name, datetime.now(timezone.utc).isoformat()),
    )


def _migration_001_initial_schema(cursor) -> None:
    user_id = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id {user_id},
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT NOT NULL
        )
    """)

    waf_id = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS waf_rules (
            id {waf_id},
            pattern TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    """)

    auth_id = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS auth_users (
            id {auth_id},
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id {auth_id},
            user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
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
            scan_preset TEXT NOT NULL DEFAULT 'standard' CHECK (scan_preset IN ('quick', 'standard', 'deep')),
            created_by BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE RESTRICT,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_members (
            project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
            created_at TEXT NOT NULL,
            PRIMARY KEY (project_id, user_id)
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id {auth_id},
            job_id TEXT NOT NULL UNIQUE,
            project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            requested_by BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE RESTRICT,
            target TEXT NOT NULL,
            preset TEXT NOT NULL CHECK (preset IN ('quick', 'standard', 'deep')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'analyzing', 'correlating', 'reporting', 'completed', 'failed', 'cancelled')),
            progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
            result_json TEXT,
            new_findings INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_connections (
            user_id BIGINT PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
            github_login TEXT NOT NULL,
            token_encrypted TEXT NOT NULL,
            scopes TEXT NOT NULL,
            connected_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_oauth_states (
            state_hash TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
            verifier_encrypted TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS notification_channels (
            id {auth_id},
            project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            channel_type TEXT NOT NULL,
            config_encrypted TEXT NOT NULL,
            events TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE RESTRICT,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS notification_deliveries (
            id {auth_id},
            channel_id BIGINT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS audit_events (
            id {auth_id},
            actor_id BIGINT REFERENCES auth_users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)


def _migration_002_sessions_and_indexes(cursor) -> None:
    identity = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id {identity},
            user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            csrf_token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_runs_project_id ON scan_runs(project_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_runs_job_id ON scan_runs(job_id)",
        "CREATE INDEX IF NOT EXISTS idx_notification_channels_project ON notification_channels(project_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(id)",
    ):
        cursor.execute(statement)


def _migration_003_github_webhook_deliveries(cursor) -> None:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
            delivery_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            repository TEXT NOT NULL,
            received_at TEXT NOT NULL
        )
    """)


MIGRATIONS = (
    Migration(1, "initial_schema", _migration_001_initial_schema),
    Migration(2, "server_sessions_and_indexes", _migration_002_sessions_and_indexes),
    Migration(3, "github_webhook_deliveries", _migration_003_github_webhook_deliveries),
)

CURRENT_SCHEMA_VERSION = MIGRATIONS[-1].version


def run_migrations(cursor) -> list[Migration]:
    applied_versions = _applied_migration_versions(cursor)
    applied_now = []
    for migration in MIGRATIONS:
        if migration.version in applied_versions:
            continue
        migration.apply(cursor)
        _record_migration(cursor, migration)
        applied_now.append(migration)
    return applied_now


def _seed_default_rows(cursor, *, reset: bool = False) -> None:
    if reset:
        cursor.execute("DELETE FROM users")
    if cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, role, api_key) VALUES (?, ?, ?)",
            DEFAULT_USERS,
        )

    if reset:
        cursor.execute("DELETE FROM waf_rules")
    if cursor.execute("SELECT COUNT(*) FROM waf_rules").fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
            DEFAULT_WAF_RULES,
        )


def initialize_database(*, reset: bool = False):
    if not USING_POSTGRES:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    run_migrations(cursor)
    _seed_default_rows(cursor, reset=reset)

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
redis_client: Any
try:
    _temp_client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=0.5)
    _temp_client.ping()
    redis_client = _temp_client
    REDIS_AVAILABLE = True
except Exception:
    redis_client = InMemoryRedis()
    REDIS_AVAILABLE = False
