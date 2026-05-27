import sqlite3
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
local_root = BASE_DIR.parent

if os.environ.get("VERCEL"):
    DB_PATH = Path("/tmp/aegis_demo.db")
    PROJECT_ROOT = Path("/tmp")
    DOWNLOAD_DIR = Path("/tmp/downloads")
    SCANS_DIR = Path("/tmp/scans")
else:
    data_dir = os.environ.get("AEGIS_DATA_DIR")
    if data_dir:
        PROJECT_ROOT = Path(data_dir)
        DB_PATH = PROJECT_ROOT / "aegis_demo.db"
        DOWNLOAD_DIR = PROJECT_ROOT / "downloads"
        SCANS_DIR = PROJECT_ROOT / "scans"
    else:
        try:
            test_file = local_root / ".test_write"
            test_file.touch()
            test_file.unlink()
            
            PROJECT_ROOT = local_root
            DB_PATH = BASE_DIR / "aegis_demo.db"
            DOWNLOAD_DIR = BASE_DIR / "downloads"
            SCANS_DIR = PROJECT_ROOT / "scans"
        except (IOError, OSError):
            user_root = Path.home() / ".aegis"
            user_root.mkdir(parents=True, exist_ok=True)
            
            PROJECT_ROOT = user_root
            DB_PATH = user_root / "aegis_demo.db"
            DOWNLOAD_DIR = user_root / "downloads"
            SCANS_DIR = user_root / "scans"


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT NOT NULL
        )
    """)

    cursor.execute("DELETE FROM users")

    users = [
        ("admin", "administrator", "ADMIN-API-KEY-12345"),
        ("devuser", "developer", "DEV-API-KEY-67890"),
        ("guest", "guest", "GUEST-API-KEY-00000")
    ]

    cursor.executemany(
        "INSERT INTO users (username, role, api_key) VALUES (?, ?, ?)",
        users
    )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waf_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    """)

    cursor.execute("DELETE FROM waf_rules")

    waf_rules = [
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
        ("localhost|127\\.0\\.0\\.1", "SSRF (Localhost lookup blocker)", 1)
    ]

    cursor.executemany(
        "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
        waf_rules
    )

    conn.commit()
    conn.close()

import redis
import threading

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
try:
    _temp_client = redis.Redis(host=REDIS_HOST, port=6379, socket_connect_timeout=0.5)
    _temp_client.ping()
    redis_client = _temp_client
    REDIS_AVAILABLE = True
except Exception:
    redis_client = InMemoryRedis()
    REDIS_AVAILABLE = False

