#!/usr/bin/env python3
"""Create and verify a recoverable SQLite snapshot for local Aegis deployments."""

import argparse
import sqlite3
import tempfile
from pathlib import Path


def verify_recovery(database: Path) -> dict:
    if not database.is_file():
        raise ValueError(f"Database does not exist: {database}")
    with tempfile.TemporaryDirectory(prefix="aegis-recovery-") as temporary:
        snapshot = Path(temporary) / "snapshot.db"
        restored = Path(temporary) / "restored.db"
        with sqlite3.connect(database) as source, sqlite3.connect(snapshot) as backup:
            source.backup(backup)
        restored.write_bytes(snapshot.read_bytes())
        with sqlite3.connect(restored) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            schema_version = connection.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]
            projects = connection.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
            scans = connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
            findings = connection.execute("SELECT COUNT(*) FROM security_findings").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"Restored database integrity failed: {integrity}")
        return {
            "status": "passed",
            "schema_version": int(schema_version),
            "projects": int(projects),
            "scan_runs": int(scans),
            "security_findings": int(findings),
            "snapshot_bytes": snapshot.stat().st_size,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    arguments = parser.parse_args()
    for key, value in verify_recovery(arguments.database).items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
