import os
import time
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
    SCANS_DIR = Path("/tmp/scans")
else:
    data_dir = os.environ.get("AEGIS_DATA_DIR")
    if data_dir:
        data_root = Path(data_dir).expanduser().resolve()
        DB_PATH = _database_path(data_root)
        SCANS_DIR = data_root / "scans"
    else:
        try:
            test_file = local_root / ".test_write"
            test_file.touch()
            test_file.unlink()

            DB_PATH = _database_path(BASE_DIR)
            SCANS_DIR = local_root / "scans"
        except (IOError, OSError):
            user_root = Path.home() / ".aegis"
            user_root.mkdir(parents=True, exist_ok=True)

            DB_PATH = _database_path(user_root)
            SCANS_DIR = user_root / "scans"


DATABASE_URL = os.environ.get("DATABASE_URL", "")
USING_POSTGRES = DATABASE_URL.startswith(("postgresql://", "postgres://"))
_postgres_pool: Any = None
_postgres_pool_pid: int | None = None
_postgres_pool_lock = threading.Lock()


def _get_postgres_pool():
    global _postgres_pool, _postgres_pool_pid
    try:
        from psycopg_pool import ConnectionPool
    except ImportError as exc:
        raise RuntimeError("PostgreSQL requires psycopg pool. Install production dependencies.") from exc
    with _postgres_pool_lock:
        if _postgres_pool is None or _postgres_pool_pid != os.getpid():
            _postgres_pool = ConnectionPool(
                DATABASE_URL,
                min_size=0,
                max_size=4,
                timeout=5,
                kwargs={"connect_timeout": 5},
                open=True,
            )
            _postgres_pool_pid = os.getpid()
        return _postgres_pool


def close_database_pool() -> None:
    global _postgres_pool, _postgres_pool_pid
    with _postgres_pool_lock:
        if _postgres_pool is not None and _postgres_pool_pid == os.getpid():
            _postgres_pool.close()
        _postgres_pool = None
        _postgres_pool_pid = None


def _reset_postgres_pool_lock() -> None:
    global _postgres_pool_lock
    _postgres_pool_lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    # RQ forks jobs: close idle sockets before the fork and replace child locks.
    os.register_at_fork(
        before=close_database_pool,
        after_in_child=_reset_postgres_pool_lock,
    )


class PostgresConnection:
    """Small DB-API adapter so application SQL can remain portable."""

    def __init__(self, connection, pool=None):
        self._connection = connection
        self._pool = pool
        self._pid = os.getpid()
        self._closed = False

    def _active_connection(self):
        if self._closed:
            raise RuntimeError("Database connection is closed.")
        if self._pid != os.getpid():
            raise RuntimeError("Database connection belongs to a different process.")
        return self._connection

    @staticmethod
    def _sql(statement: str) -> str:
        return statement.replace("?", "%s")

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()):
        cursor = self._active_connection().execute(self._sql(statement), parameters)
        return PostgresCursor(cursor, self)

    def executemany(self, statement: str, parameters):
        return self.cursor().executemany(statement, parameters)

    def cursor(self):
        return PostgresCursor(self._active_connection().cursor(), self)

    def commit(self):
        return self._active_connection().commit()

    def rollback(self):
        return self._active_connection().rollback()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._pid != os.getpid():
            return
        if self._pool is not None:
            self._pool.putconn(self._connection)
        else:
            self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type:
                self.rollback()
            else:
                self.commit()
        finally:
            self.close()


class PostgresCursor:
    def __init__(self, cursor, connection=None):
        self._cursor = cursor
        self._connection = connection

    def _active_cursor(self):
        if self._connection is not None:
            self._connection._active_connection()
        return self._cursor

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()):
        self._active_cursor().execute(statement.replace("?", "%s"), parameters)
        return self

    def executemany(self, statement: str, parameters):
        self._active_cursor().executemany(statement.replace("?", "%s"), parameters)
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount


class SQLiteConnection:
    """SQLite DB-API adapter with a context manager that always closes.

    ``sqlite3.Connection`` commits or rolls back on context exit but leaves the
    underlying file descriptor open.  Application callers consistently use
    ``with get_connection()``, so this adapter gives SQLite the same lifecycle
    guarantees as the PostgreSQL adapter.
    """

    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection
        connection.create_function(
            "unicode_lower", 1,
            lambda value: value.lower() if value is not None else None,
            deterministic=True,
        )

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()):
        return self._connection.execute(statement, parameters)

    def executemany(self, statement: str, parameters):
        return self._connection.executemany(statement, parameters)

    def cursor(self):
        return self._connection.cursor()

    def commit(self):
        return self._connection.commit()

    def rollback(self):
        return self._connection.rollback()

    @property
    def in_transaction(self) -> bool:
        return self._connection.in_transaction

    def close(self):
        return self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type:
                self.rollback()
            else:
                self.commit()
        finally:
            self.close()


def get_connection():
    if USING_POSTGRES:
        pool = _get_postgres_pool()
        return PostgresConnection(pool.getconn(), pool)
    connection = SQLiteConnection(sqlite3.connect(DB_PATH))
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


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


def _migration_004_scan_artifacts(cursor) -> None:
    identity = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS scan_artifacts (
            id {identity},
            scan_run_id BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (scan_run_id, name)
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_artifacts_run ON scan_artifacts(scan_run_id)"
    )


def _migration_005_tenant_and_identity_hardening(cursor) -> None:
    """Make tenant boundaries and credential state first-class database data."""
    identity = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS tenants (
            id {identity},
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    tenant = cursor.execute("SELECT id FROM tenants ORDER BY id LIMIT 1").fetchone()
    if tenant:
        tenant_id = int(tenant[0])
    else:
        now = datetime.now(timezone.utc).isoformat()
        insert = "INSERT INTO tenants (slug, name, created_at) VALUES (?, ?, ?)"
        if USING_POSTGRES:
            insert += " RETURNING id"
        result = cursor.execute(insert, ("default", "Default workspace", now))
        tenant_id = int(result.fetchone()[0]) if USING_POSTGRES else 1

    # These migrations intentionally use a concrete default so existing rows are
    # assigned atomically. Application writes always provide/derive tenant scope.
    for statement in (
        f"ALTER TABLE auth_users ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT {tenant_id}",
        "ALTER TABLE auth_users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE auth_users ADD COLUMN locked_until TEXT",
        "ALTER TABLE auth_users ADD COLUMN last_login_at TEXT",
        f"ALTER TABLE projects ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT {tenant_id}",
        f"ALTER TABLE scan_runs ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT {tenant_id}",
        f"ALTER TABLE audit_events ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT {tenant_id}",
        "ALTER TABLE auth_tokens ADD COLUMN scopes TEXT NOT NULL DEFAULT 'read'",
        "ALTER TABLE auth_tokens ADD COLUMN last_used_at TEXT",
        "ALTER TABLE auth_sessions ADD COLUMN authenticated_at TEXT",
    ):
        cursor.execute(statement)

    cursor.execute("UPDATE auth_sessions SET authenticated_at = created_at WHERE authenticated_at IS NULL")
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_auth_users_tenant ON auth_users(tenant_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_runs_tenant ON scan_runs(tenant_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events(tenant_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_auth_tokens_expiry ON auth_tokens(expires_at)",
    ):
        cursor.execute(statement)


def _migration_006_webhook_integrity(cursor) -> None:
    cursor.execute(
        "ALTER TABLE github_webhook_deliveries ADD COLUMN payload_sha256 TEXT"
    )
    cursor.execute(
        "ALTER TABLE github_webhook_deliveries ADD COLUMN status TEXT NOT NULL DEFAULT 'accepted'"
    )
    cursor.execute(
        "ALTER TABLE github_webhook_deliveries ADD COLUMN processed_at TEXT"
    )


def _migration_007_mfa(cursor) -> None:
    for statement in (
        "ALTER TABLE auth_users ADD COLUMN mfa_pending_secret_encrypted TEXT",
        "ALTER TABLE auth_users ADD COLUMN mfa_secret_encrypted TEXT",
        "ALTER TABLE auth_users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE auth_users ADD COLUMN mfa_recovery_hashes TEXT",
    ):
        cursor.execute(statement)


def _migration_008_mfa_replay_protection(cursor) -> None:
    cursor.execute("ALTER TABLE auth_users ADD COLUMN mfa_last_counter BIGINT")


def _migration_009_append_only_audit_chain(cursor) -> None:
    cursor.execute("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT")
    cursor.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT")
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_hash ON audit_events(event_hash)"
    )
    if USING_POSTGRES:
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_reject_audit_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit_events are append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
        cursor.execute("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events")
        cursor.execute("""
            CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION aegis_reject_audit_mutation()
        """)
        cursor.execute("""
            CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION aegis_reject_audit_mutation()
        """)
    else:
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END
        """)


def _migration_010_github_app_checks(cursor) -> None:
    for statement in (
        "ALTER TABLE scan_runs ADD COLUMN source_revision TEXT",
        "ALTER TABLE scan_runs ADD COLUMN source_ref TEXT",
        "ALTER TABLE scan_runs ADD COLUMN github_installation_id BIGINT",
        "ALTER TABLE scan_runs ADD COLUMN github_pull_request INTEGER",
        "ALTER TABLE scan_runs ADD COLUMN github_check_run_id BIGINT",
    ):
        cursor.execute(statement)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_runs_github_check ON scan_runs(github_check_run_id)"
    )


def _migration_011_tenant_consistency_guards(cursor) -> None:
    if USING_POSTGRES:
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_project_tenant()
            RETURNS trigger AS $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM auth_users
                    WHERE id = NEW.created_by AND tenant_id = NEW.tenant_id
                ) THEN RAISE EXCEPTION 'project tenant mismatch'; END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_scan_tenant()
            RETURNS trigger AS $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.requested_by
                    WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
                    AND u.tenant_id = NEW.tenant_id
                ) THEN RAISE EXCEPTION 'scan tenant mismatch'; END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_member_tenant()
            RETURNS trigger AS $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.user_id
                    WHERE p.id = NEW.project_id AND p.tenant_id = u.tenant_id
                ) THEN RAISE EXCEPTION 'project member tenant mismatch'; END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_prevent_tenant_change()
            RETURNS trigger AS $$
            BEGIN
                IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
                    RAISE EXCEPTION 'tenant identity is immutable';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        for table, function in (
            ("projects", "aegis_validate_project_tenant"),
            ("scan_runs", "aegis_validate_scan_tenant"),
            ("project_members", "aegis_validate_member_tenant"),
        ):
            cursor.execute(f"DROP TRIGGER IF EXISTS {table}_tenant_guard ON {table}")
            cursor.execute(
                f"""CREATE TRIGGER {table}_tenant_guard BEFORE INSERT OR UPDATE ON {table}
                    FOR EACH ROW EXECUTE FUNCTION {function}()"""
            )
        for table in ("auth_users", "projects", "scan_runs"):
            cursor.execute(f"DROP TRIGGER IF EXISTS {table}_tenant_immutable ON {table}")
            cursor.execute(
                f"""CREATE TRIGGER {table}_tenant_immutable BEFORE UPDATE OF tenant_id ON {table}
                    FOR EACH ROW EXECUTE FUNCTION aegis_prevent_tenant_change()"""
            )
    else:
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS projects_tenant_guard
            BEFORE INSERT ON projects
            WHEN NOT EXISTS (
                SELECT 1 FROM auth_users
                WHERE id = NEW.created_by AND tenant_id = NEW.tenant_id
            )
            BEGIN SELECT RAISE(ABORT, 'project tenant mismatch'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS projects_tenant_update_guard
            BEFORE UPDATE OF tenant_id, created_by ON projects
            WHEN NOT EXISTS (
                SELECT 1 FROM auth_users
                WHERE id = NEW.created_by AND tenant_id = NEW.tenant_id
            )
            BEGIN SELECT RAISE(ABORT, 'project tenant mismatch'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS scan_runs_tenant_guard
            BEFORE INSERT ON scan_runs
            WHEN NOT EXISTS (
                SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.requested_by
                WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
                AND u.tenant_id = NEW.tenant_id
            )
            BEGIN SELECT RAISE(ABORT, 'scan tenant mismatch'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS scan_runs_tenant_update_guard
            BEFORE UPDATE OF project_id, requested_by, tenant_id ON scan_runs
            WHEN NOT EXISTS (
                SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.requested_by
                WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
                AND u.tenant_id = NEW.tenant_id
            )
            BEGIN SELECT RAISE(ABORT, 'scan tenant mismatch'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS project_members_tenant_guard
            BEFORE INSERT ON project_members
            WHEN NOT EXISTS (
                SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.user_id
                WHERE p.id = NEW.project_id AND p.tenant_id = u.tenant_id
            )
            BEGIN SELECT RAISE(ABORT, 'project member tenant mismatch'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS project_members_tenant_update_guard
            BEFORE UPDATE OF project_id, user_id ON project_members
            WHEN NOT EXISTS (
                SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.user_id
                WHERE p.id = NEW.project_id AND p.tenant_id = u.tenant_id
            )
            BEGIN SELECT RAISE(ABORT, 'project member tenant mismatch'); END
        """)
        for table in ("auth_users", "projects", "scan_runs"):
            cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS {table}_tenant_immutable
                BEFORE UPDATE OF tenant_id ON {table}
                WHEN OLD.tenant_id != NEW.tenant_id
                BEGIN SELECT RAISE(ABORT, 'tenant identity is immutable'); END
            """)


def _migration_012_webhook_scan_link(cursor) -> None:
    """Link webhook deliveries to scans without rewriting an applied migration."""
    if USING_POSTGRES:
        cursor.execute("""
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
            AND table_name = 'github_webhook_deliveries'
            AND column_name = 'scan_run_id'
        """)
        column_exists = cursor.fetchone() is not None
    else:
        cursor.execute("PRAGMA table_info(github_webhook_deliveries)")
        column_exists = any(row[1] == "scan_run_id" for row in cursor.fetchall())
    if not column_exists:
        cursor.execute(
            "ALTER TABLE github_webhook_deliveries ADD COLUMN scan_run_id BIGINT"
        )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_github_webhook_scan "
        "ON github_webhook_deliveries(scan_run_id)"
    )


def _migration_013_durable_findings(cursor) -> None:
    identity = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS security_findings (
            id {identity},
            tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            tool TEXT NOT NULL,
            rule_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            path TEXT,
            line_number INTEGER,
            status TEXT NOT NULL DEFAULT 'open' CHECK (
                status IN ('open', 'acknowledged', 'accepted', 'false_positive', 'resolved')
            ),
            owner_id BIGINT REFERENCES auth_users(id) ON DELETE SET NULL,
            due_at TEXT,
            ticket_url TEXT,
            resolution_note TEXT,
            accepted_until TEXT,
            first_seen_run_id BIGINT REFERENCES scan_runs(id) ON DELETE SET NULL,
            last_seen_run_id BIGINT REFERENCES scan_runs(id) ON DELETE SET NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count > 0),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (project_id, fingerprint)
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS finding_occurrences (
            id {identity},
            finding_id BIGINT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
            scan_run_id BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            raw_json TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            UNIQUE (finding_id, scan_run_id)
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS finding_events (
            id {identity},
            finding_id BIGINT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
            actor_id BIGINT REFERENCES auth_users(id) ON DELETE SET NULL,
            event_type TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            note TEXT,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_findings_project_status ON security_findings(project_id, status, severity)",
        "CREATE INDEX IF NOT EXISTS idx_findings_owner ON security_findings(owner_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON security_findings(project_id, last_seen_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_occurrences_run ON finding_occurrences(scan_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_events_finding ON finding_events(finding_id, id)",
    ):
        cursor.execute(statement)


def _migration_014_versioned_policies(cursor) -> None:
    identity = _identity_id_type()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS project_policies (
            id {identity},
            tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            version INTEGER NOT NULL CHECK (version > 0),
            name TEXT NOT NULL,
            definition_json TEXT NOT NULL,
            definition_sha256 TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'approved', 'retired')),
            created_by BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE RESTRICT,
            approved_by BIGINT REFERENCES auth_users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            UNIQUE (project_id, version),
            UNIQUE (project_id, definition_sha256)
        )
    """)
    cursor.execute("ALTER TABLE scan_runs ADD COLUMN policy_version_id BIGINT")
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_project_policies_state ON project_policies(project_id, state, version)",
        "CREATE INDEX IF NOT EXISTS idx_scan_runs_policy ON scan_runs(policy_version_id)",
    ):
        cursor.execute(statement)


def _migration_015_external_artifact_metadata(cursor) -> None:
    if USING_POSTGRES:
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'scan_artifacts'
        """)
        columns = {row[0] for row in cursor.fetchall()}
    else:
        cursor.execute("PRAGMA table_info(scan_artifacts)")
        columns = {row[1] for row in cursor.fetchall()}
    if "backend" not in columns:
        cursor.execute(
            "ALTER TABLE scan_artifacts ADD COLUMN backend TEXT NOT NULL DEFAULT 'local'"
        )
    if "storage_key" not in columns:
        cursor.execute("ALTER TABLE scan_artifacts ADD COLUMN storage_key TEXT")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_artifacts_backend "
        "ON scan_artifacts(backend, storage_key)"
    )


def _migration_016_findings_policy_tenant_guards(cursor) -> None:
    if USING_POSTGRES:
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_finding_tenant()
            RETURNS trigger AS $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM projects p WHERE p.id = NEW.project_id
                    AND p.tenant_id = NEW.tenant_id
                ) OR (NEW.owner_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM auth_users u WHERE u.id = NEW.owner_id
                    AND u.tenant_id = NEW.tenant_id
                )) THEN RAISE EXCEPTION 'finding tenant mismatch'; END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_policy_tenant()
            RETURNS trigger AS $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.created_by
                    WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
                    AND u.tenant_id = NEW.tenant_id
                ) OR (NEW.approved_by IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM auth_users u WHERE u.id = NEW.approved_by
                    AND u.tenant_id = NEW.tenant_id
                )) THEN RAISE EXCEPTION 'policy tenant mismatch'; END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        for table, function in (
            ("security_findings", "aegis_validate_finding_tenant"),
            ("project_policies", "aegis_validate_policy_tenant"),
        ):
            cursor.execute(f"DROP TRIGGER IF EXISTS {table}_tenant_guard ON {table}")
            cursor.execute(
                f"""CREATE TRIGGER {table}_tenant_guard BEFORE INSERT OR UPDATE ON {table}
                    FOR EACH ROW EXECUTE FUNCTION {function}()"""
            )
            cursor.execute(f"DROP TRIGGER IF EXISTS {table}_tenant_immutable ON {table}")
            cursor.execute(
                f"""CREATE TRIGGER {table}_tenant_immutable BEFORE UPDATE OF tenant_id ON {table}
                    FOR EACH ROW EXECUTE FUNCTION aegis_prevent_tenant_change()"""
            )
    else:
        for operation, suffix in (("INSERT", ""), ("UPDATE", "_update")):
            cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS security_findings_tenant{suffix}_guard
                BEFORE {operation} ON security_findings
                WHEN NOT EXISTS (
                    SELECT 1 FROM projects p WHERE p.id = NEW.project_id
                    AND p.tenant_id = NEW.tenant_id
                ) OR (NEW.owner_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM auth_users u WHERE u.id = NEW.owner_id
                    AND u.tenant_id = NEW.tenant_id
                ))
                BEGIN SELECT RAISE(ABORT, 'finding tenant mismatch'); END
            """)
            cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS project_policies_tenant{suffix}_guard
                BEFORE {operation} ON project_policies
                WHEN NOT EXISTS (
                    SELECT 1 FROM projects p JOIN auth_users u ON u.id = NEW.created_by
                    WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
                    AND u.tenant_id = NEW.tenant_id
                ) OR (NEW.approved_by IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM auth_users u WHERE u.id = NEW.approved_by
                    AND u.tenant_id = NEW.tenant_id
                ))
                BEGIN SELECT RAISE(ABORT, 'policy tenant mismatch'); END
            """)
        for table in ("security_findings", "project_policies"):
            cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS {table}_tenant_immutable
                BEFORE UPDATE OF tenant_id ON {table}
                WHEN OLD.tenant_id != NEW.tenant_id
                BEGIN SELECT RAISE(ABORT, 'tenant identity is immutable'); END
            """)


def _migration_017_oidc_identity(cursor) -> None:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS oidc_states (
            state_hash TEXT PRIMARY KEY,
            verifier_encrypted TEXT NOT NULL,
            nonce TEXT NOT NULL,
            return_to TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS oidc_identities (
            issuer TEXT NOT NULL,
            subject TEXT NOT NULL,
            user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            last_login_at TEXT NOT NULL,
            PRIMARY KEY (issuer, subject),
            UNIQUE (user_id)
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_oidc_identity_user ON oidc_identities(user_id)"
    )


def _migration_018_oidc_transaction_boundary(cursor) -> None:
    """Add one-time, browser-bound OIDC transaction fields.

    Existing state rows deliberately receive empty values.  The callback path
    rejects those legacy rows instead of silently treating them as trusted,
    while the additive migration keeps the database upgrade reversible.
    """
    if USING_POSTGRES:
        cursor.execute(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'oidc_states'
            """
        )
        columns = {row[0] for row in cursor.fetchall()}
    else:
        cursor.execute("PRAGMA table_info(oidc_states)")
        columns = {row[1] for row in cursor.fetchall()}

    additions = (
        ("browser_binding_hash", "TEXT NOT NULL DEFAULT ''"),
        ("provider_metadata_encrypted", "TEXT NOT NULL DEFAULT ''"),
        ("issuer", "TEXT NOT NULL DEFAULT ''"),
        ("client_id", "TEXT NOT NULL DEFAULT ''"),
        ("redirect_uri", "TEXT NOT NULL DEFAULT ''"),
        ("reserved_at", "TEXT"),
    )
    for column, definition in additions:
        if column not in columns:
            cursor.execute(
                f"ALTER TABLE oidc_states ADD COLUMN {column} {definition}"
            )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_oidc_states_expiry "
        "ON oidc_states(expires_at, reserved_at)"
    )


def _migration_019_github_tenant_credential_lifecycle(cursor) -> None:
    """Make GitHub installation, repository, and capability state explicit."""
    identity = _identity_id_type()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_installations (
            installation_id BIGINT PRIMARY KEY,
            tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
            state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            revoked_at TEXT
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS github_repository_bindings (
            id {identity},
            project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
            installation_id BIGINT REFERENCES github_installations(installation_id)
                ON DELETE RESTRICT,
            repository_id BIGINT,
            repository_full_name TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'legacy'
                CHECK (state IN ('legacy', 'active', 'revoked')),
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            revoked_at TEXT,
            UNIQUE (project_id)
        )
    """)

    if USING_POSTGRES:
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'github_connections'
        """)
        columns = {row[0] for row in cursor.fetchall()}
    else:
        cursor.execute("PRAGMA table_info(github_connections)")
        columns = {row[1] for row in cursor.fetchall()}
    if "revoked_at" not in columns:
        cursor.execute("ALTER TABLE github_connections ADD COLUMN revoked_at TEXT")

    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_github_installations_tenant "
        "ON github_installations(tenant_id, state)",
        "CREATE INDEX IF NOT EXISTS idx_github_bindings_project "
        "ON github_repository_bindings(project_id, tenant_id, state)",
        "CREATE INDEX IF NOT EXISTS idx_github_bindings_installation "
        "ON github_repository_bindings(installation_id, state)",
        "CREATE INDEX IF NOT EXISTS idx_github_bindings_name "
        "ON github_repository_bindings(repository_full_name, state)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_github_active_repository_id "
        "ON github_repository_bindings(repository_id) "
        "WHERE state = 'active' AND repository_id IS NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_github_active_repository_name "
        "ON github_repository_bindings(repository_full_name) WHERE state = 'active'",
    ):
        cursor.execute(statement)

    # Existing project names are deliberately only placeholders.  They do not
    # authorize an App installation until an exact signed event promotes one.
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """INSERT INTO github_repository_bindings
           (project_id, tenant_id, installation_id, repository_id,
            repository_full_name, state, created_at, last_seen_at, revoked_at)
           SELECT p.id, p.tenant_id, NULL, NULL, p.github_full_name,
                  'legacy', ?, ?, NULL
           FROM projects p
           WHERE p.github_full_name IS NOT NULL AND TRIM(p.github_full_name) <> ''
             AND NOT EXISTS (
                 SELECT 1 FROM github_repository_bindings b WHERE b.project_id = p.id
             )""",
        (now, now),
    )

    if USING_POSTGRES:
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_github_installation()
            RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'UPDATE' AND (
                    OLD.installation_id IS DISTINCT FROM NEW.installation_id OR
                    OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
                ) THEN
                    RAISE EXCEPTION 'GitHub installation identity is immutable';
                END IF;
                IF TG_OP = 'UPDATE' AND OLD.state = 'revoked'
                   AND NEW.state <> 'revoked' THEN
                    RAISE EXCEPTION 'GitHub installation is revoked';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_github_binding()
            RETURNS trigger AS $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM projects p
                    WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
                ) OR (
                    NEW.state = 'active' AND (
                        NEW.installation_id IS NULL OR NEW.repository_id IS NULL
                    )
                ) OR (
                    NEW.installation_id IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM github_installations i
                        WHERE i.installation_id = NEW.installation_id
                          AND i.tenant_id = NEW.tenant_id
                    )
                ) THEN
                    RAISE EXCEPTION 'GitHub repository tenant mismatch';
                END IF;
                IF TG_OP = 'UPDATE' AND (
                    OLD.project_id IS DISTINCT FROM NEW.project_id OR
                    OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
                    OLD.repository_full_name IS DISTINCT FROM NEW.repository_full_name OR
                    (
                        OLD.state <> 'legacy' AND (
                            OLD.installation_id IS DISTINCT FROM NEW.installation_id OR
                            OLD.repository_id IS DISTINCT FROM NEW.repository_id
                        )
                    ) OR
                    (OLD.state = 'revoked' AND NEW.state <> 'revoked')
                ) THEN
                    RAISE EXCEPTION 'GitHub repository mapping is immutable';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_validate_scan_github_binding()
            RETURNS trigger AS $$
            BEGIN
                IF NEW.github_installation_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM github_repository_bindings b
                    WHERE b.project_id = NEW.project_id
                      AND b.tenant_id = NEW.tenant_id
                      AND b.installation_id = NEW.github_installation_id
                      AND b.state = 'active'
                ) THEN
                    RAISE EXCEPTION 'GitHub scan installation is not tenant-bound';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        for table, trigger in (
            ("github_installations", "github_installations_immutable"),
            ("github_repository_bindings", "github_repository_bindings_guard"),
        ):
            cursor.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")
        cursor.execute("""
            CREATE TRIGGER github_installations_immutable
            BEFORE UPDATE OF installation_id, tenant_id, state ON github_installations
            FOR EACH ROW EXECUTE FUNCTION aegis_validate_github_installation()
        """)
        cursor.execute("""
            CREATE TRIGGER github_repository_bindings_guard
            BEFORE INSERT OR UPDATE ON github_repository_bindings
            FOR EACH ROW EXECUTE FUNCTION aegis_validate_github_binding()
        """)
        cursor.execute("DROP TRIGGER IF EXISTS scan_runs_github_guard ON scan_runs")
        cursor.execute("""
            CREATE TRIGGER scan_runs_github_guard
            BEFORE INSERT OR UPDATE OF project_id, tenant_id, github_installation_id
            ON scan_runs FOR EACH ROW
            EXECUTE FUNCTION aegis_validate_scan_github_binding()
        """)
    else:
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS github_installations_immutable
            BEFORE UPDATE OF installation_id, tenant_id ON github_installations
            WHEN OLD.installation_id IS NOT NEW.installation_id
              OR OLD.tenant_id IS NOT NEW.tenant_id
            BEGIN SELECT RAISE(ABORT, 'GitHub installation identity is immutable'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS github_installations_no_resurrection
            BEFORE UPDATE OF state ON github_installations
            WHEN OLD.state = 'revoked' AND NEW.state <> 'revoked'
            BEGIN SELECT RAISE(ABORT, 'GitHub installation is revoked'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS github_repository_bindings_guard
            BEFORE INSERT ON github_repository_bindings
            WHEN NOT EXISTS (
                SELECT 1 FROM projects p
                WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
            ) OR (
                NEW.state = 'active' AND (
                    NEW.installation_id IS NULL OR NEW.repository_id IS NULL
                )
            ) OR (
                NEW.installation_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM github_installations i
                    WHERE i.installation_id = NEW.installation_id
                      AND i.tenant_id = NEW.tenant_id
                )
            )
            BEGIN SELECT RAISE(ABORT, 'GitHub repository tenant mismatch'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS github_repository_bindings_update_guard
            BEFORE UPDATE OF project_id, tenant_id, installation_id,
                repository_id, repository_full_name, state
            ON github_repository_bindings
            WHEN NOT EXISTS (
                SELECT 1 FROM projects p
                WHERE p.id = NEW.project_id AND p.tenant_id = NEW.tenant_id
            ) OR (
                NEW.state = 'active' AND (
                    NEW.installation_id IS NULL OR NEW.repository_id IS NULL
                )
            ) OR (
                NEW.installation_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM github_installations i
                    WHERE i.installation_id = NEW.installation_id
                      AND i.tenant_id = NEW.tenant_id
                )
            ) OR OLD.project_id IS NOT NEW.project_id
              OR OLD.tenant_id IS NOT NEW.tenant_id
              OR OLD.repository_full_name IS NOT NEW.repository_full_name
              OR (
                  OLD.state <> 'legacy' AND (
                      OLD.installation_id IS NOT NEW.installation_id
                      OR OLD.repository_id IS NOT NEW.repository_id
                  )
              ) OR (OLD.state = 'revoked' AND NEW.state <> 'revoked')
            BEGIN SELECT RAISE(ABORT, 'GitHub repository mapping is immutable'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS scan_runs_github_guard
            BEFORE INSERT ON scan_runs
            WHEN NEW.github_installation_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM github_repository_bindings b
                WHERE b.project_id = NEW.project_id
                  AND b.tenant_id = NEW.tenant_id
                  AND b.installation_id = NEW.github_installation_id
                  AND b.state = 'active'
            )
            BEGIN SELECT RAISE(ABORT, 'GitHub scan installation is not tenant-bound'); END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS scan_runs_github_update_guard
            BEFORE UPDATE OF project_id, tenant_id, github_installation_id ON scan_runs
            WHEN NEW.github_installation_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM github_repository_bindings b
                WHERE b.project_id = NEW.project_id
                  AND b.tenant_id = NEW.tenant_id
                  AND b.installation_id = NEW.github_installation_id
                  AND b.state = 'active'
            )
            BEGIN SELECT RAISE(ABORT, 'GitHub scan installation is not tenant-bound'); END
        """)


def _migration_020_api_token_hash_version(cursor) -> None:
    """Version API-token hashes and revoke rows that predate the marker.

    Existing rows cannot be classified safely because the old schema did not
    record whether a digest was keyed or an unsalted SHA-256 value.  They are
    therefore disabled during migration and must be reissued through the token
    API, which always records the current keyed scheme explicitly.
    """
    if USING_POSTGRES:
        cursor.execute(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'auth_tokens'
            """
        )
        columns = {row[0] for row in cursor.fetchall()}
    else:
        cursor.execute("PRAGMA table_info(auth_tokens)")
        columns = {row[1] for row in cursor.fetchall()}

    additions = (
        ("hash_scheme", "TEXT NOT NULL DEFAULT 'legacy'"),
        ("revoked_at", "TEXT"),
    )
    for column, definition in additions:
        if column not in columns:
            cursor.execute(f"ALTER TABLE auth_tokens ADD COLUMN {column} {definition}")

    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """UPDATE auth_tokens SET revoked_at = ?
           WHERE revoked_at IS NULL AND hash_scheme <> 'hmac-sha256-v1'""",
        (now,),
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_auth_tokens_scheme ON auth_tokens(hash_scheme, revoked_at)"
    )


def _migration_021_github_oauth_session_binding(cursor) -> None:
    """Bind GitHub OAuth transactions to the browser session that started them."""
    if USING_POSTGRES:
        cursor.execute(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'github_oauth_states'
            """
        )
        columns = {row[0] for row in cursor.fetchall()}
    else:
        cursor.execute("PRAGMA table_info(github_oauth_states)")
        columns = {row[1] for row in cursor.fetchall()}

    if "session_hash" not in columns:
        cursor.execute(
            "ALTER TABLE github_oauth_states ADD COLUMN session_hash TEXT NOT NULL DEFAULT ''"
        )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_github_oauth_states_session "
        "ON github_oauth_states(state_hash, session_hash)"
    )


def _migration_022_scan_result_summaries(cursor) -> None:
    from .projects import scan_result_summary

    if USING_POSTGRES:
        cursor.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'scan_runs'"
        )
        columns = {row[0] for row in cursor.fetchall()}
    else:
        cursor.execute("PRAGMA table_info(scan_runs)")
        columns = {row[1] for row in cursor.fetchall()}
    if "summary_json" not in columns:
        cursor.execute("ALTER TABLE scan_runs ADD COLUMN summary_json TEXT")

    last_id = None
    while True:
        clause = " AND id > ?" if last_id is not None else ""
        cursor.execute(
            "SELECT id, result_json FROM scan_runs "
            "WHERE summary_json IS NULL AND result_json IS NOT NULL"
            f"{clause} ORDER BY id LIMIT 100",
            (last_id,) if last_id is not None else (),
        )
        rows = cursor.fetchall()
        if not rows:
            break
        summaries = []
        for run_id, result_json in rows:
            try:
                result = json.loads(result_json)
                if not isinstance(result, dict):
                    raise ValueError("Stored scan result must be an object.")
            except (TypeError, ValueError, RecursionError):
                result = {"error": "Stored scan result could not be read."}
            summaries.append((json.dumps(scan_result_summary(result), separators=(",", ":")), run_id))
        cursor.executemany(
            "UPDATE scan_runs SET summary_json = ? WHERE id = ? AND summary_json IS NULL",
            summaries,
        )
        last_id = rows[-1][0]


def _migration_023_evidence_signature_ledger(cursor) -> None:
    # The evidence signer records each signed scan run once. A second request
    # for the same run is refused, so a completed run cannot be re-signed.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_signatures (
            scan_run_id BIGINT PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
            job_id TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            key_id TEXT NOT NULL,
            signed_at TEXT NOT NULL
        )
    """)
    if USING_POSTGRES:
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_reject_signature_update()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'evidence_signatures are append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("DROP TRIGGER IF EXISTS evidence_signatures_no_update ON evidence_signatures")
        cursor.execute("""
            CREATE TRIGGER evidence_signatures_no_update BEFORE UPDATE ON evidence_signatures
            FOR EACH ROW EXECUTE FUNCTION aegis_reject_signature_update()
        """)
    else:
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS evidence_signatures_no_update
            BEFORE UPDATE ON evidence_signatures
            BEGIN SELECT RAISE(ABORT, 'evidence_signatures are append-only'); END
        """)


def _migration_024_final_scan_runs(cursor) -> None:
    # A finished run's decision is evidence: no role may reopen it or rewrite
    # its result. Without this, a compromised worker could move a completed
    # run back to an in-flight state and obtain a fresh signature for it.
    if USING_POSTGRES:
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_reject_final_scan_change()
            RETURNS trigger AS $$
            BEGIN
                IF OLD.state IN ('completed', 'failed', 'cancelled') AND (
                    NEW.state IS DISTINCT FROM OLD.state
                    OR NEW.result_json IS DISTINCT FROM OLD.result_json
                    OR NEW.new_findings IS DISTINCT FROM OLD.new_findings
                    OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
                ) THEN
                    RAISE EXCEPTION 'finished scan runs are immutable';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("DROP TRIGGER IF EXISTS scan_runs_final_immutable ON scan_runs")
        cursor.execute("""
            CREATE TRIGGER scan_runs_final_immutable BEFORE UPDATE ON scan_runs
            FOR EACH ROW EXECUTE FUNCTION aegis_reject_final_scan_change()
        """)
    else:
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS scan_runs_final_immutable
            BEFORE UPDATE ON scan_runs
            WHEN OLD.state IN ('completed', 'failed', 'cancelled') AND (
                NEW.state IS NOT OLD.state
                OR NEW.result_json IS NOT OLD.result_json
                OR NEW.new_findings IS NOT OLD.new_findings
                OR NEW.completed_at IS NOT OLD.completed_at
            )
            BEGIN SELECT RAISE(ABORT, 'finished scan runs are immutable'); END
        """)


def _migration_025_least_privilege_support(cursor) -> None:
    # Artifact metadata for a finished run is evidence, like the run itself.
    if USING_POSTGRES:
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_reject_final_artifact_change()
            RETURNS trigger AS $$
            DECLARE
                target_run BIGINT;
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    target_run := OLD.scan_run_id;
                ELSE
                    target_run := NEW.scan_run_id;
                END IF;
                IF EXISTS (
                    SELECT 1 FROM scan_runs
                    WHERE id = target_run AND state IN ('completed', 'failed', 'cancelled')
                ) THEN
                    RAISE EXCEPTION 'artifacts of finished scan runs are immutable';
                END IF;
                IF TG_OP = 'DELETE' THEN
                    RETURN OLD;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        cursor.execute("DROP TRIGGER IF EXISTS scan_artifacts_final_immutable ON scan_artifacts")
        cursor.execute("""
            CREATE TRIGGER scan_artifacts_final_immutable
            BEFORE INSERT OR UPDATE OR DELETE ON scan_artifacts
            FOR EACH ROW EXECUTE FUNCTION aegis_reject_final_artifact_change()
        """)
        # Lets the scan worker check whether a requester's GitHub connection is
        # usable without being able to read the stored (encrypted) token.
        cursor.execute("""
            CREATE OR REPLACE FUNCTION aegis_github_connection_state(target_user BIGINT)
            RETURNS TEXT LANGUAGE sql STABLE SECURITY DEFINER
            SET search_path FROM CURRENT AS $$
                SELECT COALESCE((
                    SELECT CASE
                        WHEN revoked_at IS NOT NULL OR token_encrypted IS NULL OR token_encrypted = ''
                        THEN 'unavailable' ELSE 'usable' END
                    FROM github_connections WHERE user_id = target_user
                ), 'none')
            $$
        """)
        cursor.execute("REVOKE ALL ON FUNCTION aegis_github_connection_state(BIGINT) FROM PUBLIC")
    else:
        for operation, row in (("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")):
            cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS scan_artifacts_final_{operation.lower()}
                BEFORE {operation} ON scan_artifacts
                WHEN EXISTS (
                    SELECT 1 FROM scan_runs
                    WHERE id = {row}.scan_run_id AND state IN ('completed', 'failed', 'cancelled')
                )
                BEGIN SELECT RAISE(ABORT, 'artifacts of finished scan runs are immutable'); END
            """)


# PostgreSQL logins for the narrow services. Each gets only what its code
# reads or writes, and none owns a table, so none can disable the triggers
# that keep audit events, signatures, and finished runs immutable.
SERVICE_DATABASE_ROLES: dict[str, dict[str, Any]] = {
    "aegis_worker": {
        "login_env": "AEGIS_DB_WORKER_PASSWORD",
        "grants": (
            ("SELECT", "projects"),
            ("SELECT", "tenants"),
            ("SELECT", "scan_runs"),
            ("UPDATE (state, progress, result_json, summary_json, new_findings, completed_at)", "scan_runs"),
            ("SELECT, INSERT, DELETE", "scan_artifacts"),
            ("SELECT, INSERT, UPDATE", "security_findings"),
            ("SELECT, INSERT, UPDATE", "finding_occurrences"),
            ("SELECT, INSERT", "finding_events"),
            ("SELECT", "project_members"),
            ("SELECT", "project_policies"),
            ("SELECT (id, tenant_id, role, active, username)", "auth_users"),
            ("SELECT", "github_repository_bindings"),
            ("SELECT", "github_installations"),
        ),
        "functions": ("aegis_github_connection_state(BIGINT)",),
    },
    "aegis_signer": {
        "login_env": "AEGIS_DB_SIGNER_PASSWORD",
        "grants": (
            ("SELECT (id, job_id, project_id, state)", "scan_runs"),
            ("SELECT (id, tenant_id)", "projects"),
            ("SELECT, INSERT", "evidence_signatures"),
        ),
        "functions": (),
    },
    "aegis_github_broker": {
        "login_env": "AEGIS_DB_BROKER_PASSWORD",
        "grants": (
            ("SELECT (id, state, requested_by, github_installation_id, github_check_run_id, project_id)", "scan_runs"),
            ("SELECT (id, tenant_id, github_full_name, created_by)", "projects"),
            ("SELECT", "github_repository_bindings"),
            ("SELECT", "github_installations"),
            ("SELECT (user_id, token_encrypted, revoked_at)", "github_connections"),
            ("SELECT (id, tenant_id, active, username, role)", "auth_users"),
        ),
        "functions": (),
    },
    "aegis_notifier": {
        "login_env": "AEGIS_DB_NOTIFIER_PASSWORD",
        "grants": (
            ("SELECT", "notification_channels"),
            ("INSERT", "notification_deliveries"),
        ),
        "functions": (),
    },
}


def apply_service_roles(connection) -> list[str]:
    """Create or refresh the service logins whose passwords are configured.

    Runs as the schema owner after migrations, on every start, so grants follow
    schema changes. Returns the roles it configured.
    """
    if not USING_POSTGRES:
        return []
    from psycopg import sql

    raw = connection._active_connection()
    schema = raw.execute("SELECT current_schema()").fetchone()[0]
    # Restores made with --no-privileges reset function ACLs; keep this one narrow.
    raw.execute("REVOKE ALL ON FUNCTION aegis_github_connection_state(BIGINT) FROM PUBLIC")
    configured = []
    for role, spec in SERVICE_DATABASE_ROLES.items():
        password = os.environ.get(spec["login_env"], "")
        if not password:
            continue
        exists = raw.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        # Only a superuser may restate SUPERUSER/BYPASSRLS on ALTER; services
        # re-check these attributes themselves at startup.
        attributes = "LOGIN" if exists else "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
        raw.execute(sql.SQL(
            ("ALTER" if exists else "CREATE") + " ROLE {} WITH " + attributes + " PASSWORD {}"
        ).format(sql.Identifier(role), sql.Literal(password)))
        raw.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM {}").format(
            sql.Identifier(schema), sql.Identifier(role)))
        raw.execute(sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA {} FROM {}").format(
            sql.Identifier(schema), sql.Identifier(role)))
        raw.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            sql.Identifier(schema), sql.Identifier(role)))
        for privileges, table in spec["grants"]:
            # Privileges and table names are fixed literals defined above.
            raw.execute(sql.SQL("GRANT " + privileges + " ON {} TO {}").format(
                sql.Identifier(schema, table), sql.Identifier(role)))
        if any("INSERT" in privileges for privileges, _ in spec["grants"]):
            raw.execute(sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)))
        for function in spec["functions"]:
            raw.execute(sql.SQL("GRANT EXECUTE ON FUNCTION " + function + " TO {}").format(
                sql.Identifier(role)))
        configured.append(role)
    return configured


def require_least_privilege_role(timeout: float = 120.0) -> None:
    """Refuse to run a production service as a superuser or the schema owner.

    Waits for the role to exist, since the dashboard creates it at startup.
    """
    if not USING_POSTGRES:
        raise RuntimeError("Production services require PostgreSQL.")
    deadline = time.monotonic() + timeout
    while True:
        try:
            with get_connection() as connection:
                row = connection.execute(
                    """SELECT r.rolsuper OR r.rolcreaterole OR r.rolbypassrls,
                              pg_get_userbyid(c.relowner) = current_user, current_user
                       FROM pg_roles r, pg_class c
                       WHERE r.rolname = current_user AND c.relname = 'scan_runs'
                         AND c.relnamespace = current_schema()::regnamespace"""
                ).fetchone()
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)
    if not row:
        raise RuntimeError("The Aegis schema has not been created yet.")
    if row[0] or row[1]:
        raise RuntimeError(
            f"Database role {row[2]!r} is too privileged for this service: use its "
            "least-privilege login (for example aegis_worker), not the schema owner."
        )


def _migration_026_drop_demo_lab_tables(cursor) -> None:
    cursor.execute("DROP TABLE IF EXISTS waf_rules")
    cursor.execute("DROP TABLE IF EXISTS users")


MIGRATIONS = (
    Migration(1, "initial_schema", _migration_001_initial_schema),
    Migration(2, "server_sessions_and_indexes", _migration_002_sessions_and_indexes),
    Migration(3, "github_webhook_deliveries", _migration_003_github_webhook_deliveries),
    Migration(4, "immutable_scan_artifacts", _migration_004_scan_artifacts),
    Migration(5, "tenant_and_identity_hardening", _migration_005_tenant_and_identity_hardening),
    Migration(6, "github_webhook_integrity", _migration_006_webhook_integrity),
    Migration(7, "totp_mfa", _migration_007_mfa),
    Migration(8, "mfa_replay_protection", _migration_008_mfa_replay_protection),
    Migration(9, "append_only_audit_chain", _migration_009_append_only_audit_chain),
    Migration(10, "github_app_checks", _migration_010_github_app_checks),
    Migration(11, "tenant_consistency_guards", _migration_011_tenant_consistency_guards),
    Migration(12, "webhook_scan_link", _migration_012_webhook_scan_link),
    Migration(13, "durable_findings", _migration_013_durable_findings),
    Migration(14, "versioned_project_policies", _migration_014_versioned_policies),
    Migration(15, "external_artifact_metadata", _migration_015_external_artifact_metadata),
    Migration(16, "findings_policy_tenant_guards", _migration_016_findings_policy_tenant_guards),
    Migration(17, "oidc_identity", _migration_017_oidc_identity),
    Migration(18, "oidc_transaction_boundary", _migration_018_oidc_transaction_boundary),
    Migration(19, "github_tenant_credential_lifecycle", _migration_019_github_tenant_credential_lifecycle),
    Migration(20, "api_token_hash_version", _migration_020_api_token_hash_version),
    Migration(21, "github_oauth_session_binding", _migration_021_github_oauth_session_binding),
    Migration(22, "scan_result_summaries", _migration_022_scan_result_summaries),
    Migration(23, "evidence_signature_ledger", _migration_023_evidence_signature_ledger),
    Migration(24, "final_scan_runs", _migration_024_final_scan_runs),
    Migration(25, "least_privilege_support", _migration_025_least_privilege_support),
    Migration(26, "drop_demo_lab_tables", _migration_026_drop_demo_lab_tables),
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


def initialize_database():
    if not USING_POSTGRES:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    try:
        if USING_POSTGRES:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(?))",
                ("aegis_schema_migrations",),
            )
        run_migrations(cursor)
        apply_service_roles(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
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

    def hdel(self, name, *keys):
        with self.lock:
            values = self.storage.get(name, {})
            deleted = 0
            for key in keys:
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if key in values:
                    del values[key]
                    deleted += 1
            return deleted

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

    def hincrby(self, name, key, amount=1):
        with self.lock:
            values = self.storage.setdefault(name, {})
            current = values.get(key, b"0")
            if isinstance(current, bytes):
                current = current.decode()
            updated = int(current) + int(amount)
            values[key] = str(updated).encode()
            return updated

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
    _temp_client = redis.Redis.from_url(
        REDIS_URL, socket_connect_timeout=0.5, socket_timeout=1.0,
    )
    _temp_client.ping()
    redis_client = _temp_client
    REDIS_AVAILABLE = True
except Exception:
    redis_client = InMemoryRedis()
    REDIS_AVAILABLE = False
