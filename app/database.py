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

