import sqlite3

import pytest

from app import database
from app.database import PostgresConnection, PostgresCursor


def test_postgres_connection_executemany_uses_cursor():
    calls = []

    class Cursor:
        def executemany(self, statement, parameters):
            calls.append((statement, parameters))

    class Connection:
        def cursor(self):
            return Cursor()

    parameters = [(1, "report.html"), (1, "report.md")]
    result = PostgresConnection(Connection()).executemany(
        "INSERT INTO scan_artifacts (scan_run_id, name) VALUES (?, ?)",
        parameters,
    )

    assert isinstance(result, PostgresCursor)
    assert calls == [
        (
            "INSERT INTO scan_artifacts (scan_run_id, name) VALUES (%s, %s)",
            parameters,
        )
    ]


def test_sqlite_connection_context_closes_connection(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "closed.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)

    with database.get_connection() as connection:
        connection.execute("CREATE TABLE example (id INTEGER PRIMARY KEY)")

    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


def test_sqlite_connection_context_rolls_back_and_closes(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "rollback.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)

    with database.get_connection() as connection:
        connection.execute("CREATE TABLE example (value TEXT)")

    with pytest.raises(RuntimeError, match="abort"):
        with database.get_connection() as connection:
            connection.execute("INSERT INTO example (value) VALUES ('temporary')")
            raise RuntimeError("abort")

    with database.get_connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM example").fetchone()[0]

    assert count == 0
