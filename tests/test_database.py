import sqlite3
import json
import sys
import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app import database
from app.database import PostgresConnection, PostgresCursor


@pytest.fixture
def postgres_pool(monkeypatch):
    pools = []

    class Pool:
        def __init__(self, conninfo, **kwargs):
            self.conninfo = conninfo
            self.options = kwargs
            self.connection = Mock()
            self.returned = []
            self.closed = False
            pools.append(self)

        def getconn(self):
            return self.connection

        def putconn(self, connection):
            self.returned.append(connection)

        def close(self):
            self.closed = True

    monkeypatch.setitem(sys.modules, "psycopg_pool", SimpleNamespace(ConnectionPool=Pool))
    monkeypatch.setattr(database, "USING_POSTGRES", True)
    monkeypatch.setattr(database, "DATABASE_URL", "postgresql://localhost/aegis")
    monkeypatch.setattr(database, "_postgres_pool", None, raising=False)
    monkeypatch.setattr(database, "_postgres_pool_pid", None, raising=False)
    yield pools
    if hasattr(database, "close_database_pool"):
        database.close_database_pool()


def test_postgres_reuses_bounded_pool_and_returns_connections(postgres_pool):
    with database.get_connection() as first:
        result = first.execute("SELECT ?", (1,))
        cursor = first.cursor()
    with database.get_connection():
        pass

    assert len(postgres_pool) == 1
    pool = postgres_pool[0]
    assert pool.options["min_size"] == 0
    assert pool.options["max_size"] == 4
    assert pool.options["timeout"] == 5
    assert pool.options["kwargs"]["connect_timeout"] == 5
    assert pool.returned == [pool.connection, pool.connection]
    assert pool.connection.commit.call_count == 2
    pool.connection.execute.assert_called_once_with("SELECT %s", (1,))
    pool.connection.close.assert_not_called()
    with pytest.raises(RuntimeError, match="closed"):
        first.execute("SELECT 1")
    with pytest.raises(RuntimeError, match="closed"):
        cursor.execute("SELECT 1")
    with pytest.raises(RuntimeError, match="closed"):
        result.executemany("SELECT ?", [(1,)])


def test_postgres_rolls_back_and_returns_on_error(postgres_pool):
    with pytest.raises(RuntimeError, match="abort"):
        with database.get_connection():
            raise RuntimeError("abort")

    pool = postgres_pool[0]
    pool.connection.rollback.assert_called_once()
    pool.connection.commit.assert_not_called()
    assert pool.returned == [pool.connection]


def test_postgres_cursor_keeps_completed_result_metadata_after_return(postgres_pool):
    with database.get_connection() as connection:
        updated = connection.execute("UPDATE auth_sessions SET last_seen_at = ?", ("now",))
        postgres_pool[0].connection.execute.return_value.rowcount = 1

    assert bool(getattr(updated, "rowcount", 0))


def test_postgres_fork_lifecycle_closes_idle_pool_and_replaces_child_lock(postgres_pool):
    with database.get_connection():
        pass
    parent_lock = database._postgres_pool_lock

    database.close_database_pool()
    database._reset_postgres_pool_lock()

    assert postgres_pool[0].closed
    assert database._postgres_pool_lock is not parent_lock
    with database.get_connection():
        pass
    assert len(postgres_pool) == 2


@pytest.mark.parametrize("operation", ["commit", "rollback"])
def test_postgres_returns_connection_when_transaction_end_fails(postgres_pool, operation):
    connection = database.get_connection()
    pool = postgres_pool[0]
    getattr(pool.connection, operation).side_effect = RuntimeError("database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        with connection:
            if operation == "rollback":
                raise ValueError("abort")

    assert pool.returned == [pool.connection]
    connection.close()
    assert pool.returned == [pool.connection]


def test_postgres_non_context_lifecycle_and_pool_shutdown(postgres_pool):
    connection = database.get_connection()
    connection.commit()
    connection.close()
    pool = postgres_pool[0]

    pool.connection.commit.assert_called_once()
    assert pool.returned == [pool.connection]
    database.close_database_pool()
    assert pool.closed
    with database.get_connection():
        pass
    assert len(postgres_pool) == 2


def test_postgres_pool_is_not_reused_after_fork(postgres_pool, monkeypatch):
    connection = database.get_connection()
    cursor = connection.cursor()
    pool = postgres_pool[0]
    pid = database.os.getpid()
    monkeypatch.setattr(database.os, "getpid", lambda: pid + 1)

    with database.get_connection():
        pass

    assert len(postgres_pool) == 2
    assert not pool.closed
    assert pool.returned == []
    with pytest.raises(RuntimeError, match="process"):
        connection.execute("SELECT 1")
    with pytest.raises(RuntimeError, match="process"):
        cursor.execute("SELECT 1")
    connection.close()
    assert pool.returned == []
    pool.connection.close.assert_not_called()


def test_postgres_unpooled_adapter_closes_after_commit_failure():
    native_connection = Mock()
    native_connection.commit.side_effect = RuntimeError("database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        with PostgresConnection(native_connection):
            pass

    native_connection.close.assert_called_once()


def test_postgres_initialization_keeps_migrations_in_one_transaction(postgres_pool, monkeypatch):
    migration = Mock()
    monkeypatch.setattr(database, "run_migrations", migration)
    monkeypatch.setattr(database, "_seed_default_rows", Mock())

    database.initialize_database()

    pool = postgres_pool[0]
    migration.assert_called_once()
    pool.connection.cursor.return_value.execute.assert_called_once_with(
        "SELECT pg_advisory_xact_lock(hashtext(%s))", ("aegis_schema_migrations",),
    )
    pool.connection.commit.assert_called_once()
    assert pool.returned == [pool.connection]


def test_application_lifespan_closes_database_pool_on_startup_failure(monkeypatch):
    from app import main

    monkeypatch.setattr(main, "initialize_database", Mock(side_effect=RuntimeError("migration failed")))
    close_pool = Mock()
    monkeypatch.setattr(main, "close_database_pool", close_pool)

    async def startup():
        async with main.lifespan(main.app):
            pass

    with pytest.raises(RuntimeError, match="migration failed"):
        asyncio.run(startup())
    close_pool.assert_called_once()


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


@pytest.mark.parametrize("value, expected", [("Évil.py", "évil.py"), ("Straße.py", "straße.py"), (None, None)])
def test_sqlite_unicode_lower_preserves_browser_search_semantics(tmp_path, monkeypatch, value, expected):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "unicode.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)

    with database.get_connection() as connection:
        assert connection.execute("SELECT unicode_lower(?)", (value,)).fetchone()[0] == expected


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


def test_scan_summary_migration_preserves_legacy_results_and_is_idempotent(monkeypatch):
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    legacy_results = (
        json.dumps({"policy": {"status": "PASS", "reason": "safe", "findings": ["large"]},
                    "bac_report": {"status": "PASS", "exit_code": 0, "mode": "imported"}}),
        '{"policy":{"status":"PASS"}',
        "[1,2]",
        "null",
        None,
    )
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, result_json TEXT, state TEXT)")
    connection.executemany(
        "INSERT INTO scan_runs VALUES (?, ?, ?)",
        [(index, result, "completed") for index, result in enumerate(legacy_results, 1)],
    )
    before = connection.execute("SELECT id, result_json, state FROM scan_runs ORDER BY id").fetchall()

    database._migration_022_scan_result_summaries(connection.cursor())
    summaries = connection.execute("SELECT summary_json FROM scan_runs ORDER BY id").fetchall()
    database._migration_022_scan_result_summaries(connection.cursor())

    assert before == connection.execute("SELECT id, result_json, state FROM scan_runs ORDER BY id").fetchall()
    assert summaries == connection.execute("SELECT summary_json FROM scan_runs ORDER BY id").fetchall()
    assert json.loads(summaries[0][0]) == {
        "policy": {"status": "PASS", "reason": "safe"},
        "bac_report": {"status": "PASS", "exit_code": 0, "mode": "imported"},
    }
    for row in summaries[1:4]:
        summary = json.loads(row[0])
        assert summary.get("error")
        assert "policy" not in summary
        assert "bac_report" not in summary
    assert summaries[4][0] is None
    connection.close()


def test_scan_summary_migration_backfills_in_bounded_batches(monkeypatch):
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, result_json TEXT)")
    connection.executemany(
        "INSERT INTO scan_runs VALUES (?, ?)",
        [(index, '{"policy":{"status":"FAIL"}}') for index in range(250)],
    )
    batches = []

    class Cursor:
        def __init__(self):
            self.cursor = connection.cursor()
            self.statement = ""

        def execute(self, statement, parameters=()):
            self.statement = statement
            self.cursor.execute(statement, parameters)
            return self

        def fetchall(self):
            rows = self.cursor.fetchall()
            if "SELECT id, result_json" in self.statement:
                batches.append(len(rows))
            return rows

        def executemany(self, statement, parameters):
            self.cursor.executemany(statement, parameters)

    database._migration_022_scan_result_summaries(Cursor())

    assert batches == [100, 100, 50, 0]
    assert connection.execute("SELECT COUNT(*) FROM scan_runs WHERE summary_json IS NOT NULL").fetchone()[0] == 250
    connection.close()
