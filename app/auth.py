import hashlib
import hmac
import json
import os
import secrets
import base64
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import HTTPException, Request, WebSocket
from cryptography.fernet import Fernet, InvalidToken

from .database import get_connection


SESSION_COOKIE = "aegis_session"
ROLE_LEVEL = {"viewer": 10, "operator": 20, "admin": 30}
TOKEN_SCOPES = {"read", "write", "admin"}
API_TOKEN_HASH_SCHEME = "hmac-sha256-v1"
AUTH_REQUIRED = os.environ.get("AEGIS_REQUIRE_AUTH", "").lower() in {"1", "true", "yes", "on"} or (
    os.environ.get("AEGIS_ENV", "development").lower() == "production"
)
DEVELOPMENT_USERNAME = "development"
LOGIN_FAILURE_LIMIT = max(3, int(os.environ.get("AEGIS_LOGIN_FAILURE_LIMIT", "5")))
LOGIN_LOCKOUT_SECONDS = max(60, int(os.environ.get("AEGIS_LOGIN_LOCKOUT_SECONDS", "900")))
RECENT_AUTH_SECONDS = max(60, int(os.environ.get("AEGIS_RECENT_AUTH_SECONDS", "600")))


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    role: str
    csrf_token: str
    tenant_id: int = 1
    scopes: tuple[str, ...] = ("*",)
    auth_method: str = "session"


def _secret() -> bytes:
    value = os.environ.get("AEGIS_SESSION_SECRET", "")
    if not value and not AUTH_REQUIRED:
        value = "development-session-secret-not-for-production"
    return value.encode()


def _session_token_hash(token: str) -> str:
    return hmac.new(_secret(), token.encode(), hashlib.sha256).hexdigest()


def _token_pepper() -> bytes:
    value = os.environ.get("AEGIS_TOKEN_PEPPER", "")
    if not value:
        value = os.environ.get("AEGIS_SESSION_SECRET", "")
    if not value and not AUTH_REQUIRED:
        value = "development-token-pepper-not-for-production"
    return value.encode()


def hash_api_token(token: str) -> str:
    """Key API token hashes so a database disclosure is not enough to test guesses."""
    return hmac.new(_token_pepper(), f"api:{token}".encode(), hashlib.sha256).hexdigest()


def _credential_fernet() -> Fernet:
    key = os.environ.get("AEGIS_ENCRYPTION_KEY", "")
    if not key:
        raise RuntimeError("AEGIS_ENCRYPTION_KEY is required to configure MFA.")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("AEGIS_ENCRYPTION_KEY must be a valid Fernet key.") from exc


def _totp(secret: str, timestamp: int | None = None) -> str:
    padded = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((timestamp if timestamp is not None else time.time()) // 30)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _verify_totp(secret: str, code: str) -> int | None:
    if not code.isdigit() or len(code) != 6:
        return None
    now = int(time.time())
    for drift in (-1, 0, 1):
        timestamp = now + drift * 30
        if hmac.compare_digest(_totp(secret, timestamp), code):
            return timestamp // 30
    return None


def _decrypt_mfa_secret(encrypted: str) -> str | None:
    try:
        return _credential_fernet().decrypt(encrypted.encode()).decode()
    except (InvalidToken, RuntimeError, ValueError):
        return None


def _consume_second_factor(
    connection, user_id: int, code: str, encrypted_secret: str, recovery_json: str | None
) -> bool:
    secret = _decrypt_mfa_secret(encrypted_secret)
    normalized = code.strip().replace(" ", "").replace("-", "").upper()
    counter = _verify_totp(secret, normalized) if secret else None
    if counter is not None:
        updated = connection.execute(
            """UPDATE auth_users SET mfa_last_counter = ?
               WHERE id = ? AND (mfa_last_counter IS NULL OR mfa_last_counter < ?)""",
            (counter, user_id, counter),
        )
        return bool(getattr(updated, "rowcount", 0))
    try:
        recovery_hashes = list(json.loads(recovery_json or "[]"))
    except (json.JSONDecodeError, TypeError):
        return False
    candidate = hash_api_token(f"recovery:{normalized}")
    match = next(
        (value for value in recovery_hashes if hmac.compare_digest(value, candidate)),
        None,
    )
    if not match:
        return False
    recovery_hashes.remove(match)
    updated = connection.execute(
        """UPDATE auth_users SET mfa_recovery_hashes = ?
           WHERE id = ? AND COALESCE(mfa_recovery_hashes, '[]') = ?""",
        (
            json.dumps(recovery_hashes, separators=(",", ":")),
            user_id,
            recovery_json or "[]",
        ),
    )
    return bool(getattr(updated, "rowcount", 0))


def begin_mfa_setup(user_id: int, username: str) -> dict:
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    encrypted = _credential_fernet().encrypt(secret.encode()).decode()
    with get_connection() as connection:
        updated = connection.execute(
            """UPDATE auth_users SET mfa_pending_secret_encrypted = ?
               WHERE id = ? AND active = 1""",
            (encrypted, user_id),
        )
        if not getattr(updated, "rowcount", 0):
            raise ValueError("Active user not found.")
    issuer = os.environ.get("AEGIS_MFA_ISSUER", "Aegis")[:64]
    label = quote(f"{issuer}:{username}")
    uri = (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )
    return {"secret": secret, "otpauth_uri": uri}


def confirm_mfa_setup(user_id: int, code: str) -> list[str]:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT mfa_pending_secret_encrypted FROM auth_users
               WHERE id = ? AND active = 1""",
            (user_id,),
        ).fetchone()
        if not row or not row[0]:
            raise ValueError("MFA setup has not been started.")
        secret = _decrypt_mfa_secret(row[0])
        counter = _verify_totp(secret, code.strip()) if secret else None
        if secret is None or counter is None:
            raise ValueError("The authenticator code is invalid.")
        recovery_codes = [
            f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
            for _ in range(10)
        ]
        recovery_hashes = [
            hash_api_token(f"recovery:{item.replace('-', '')}")
            for item in recovery_codes
        ]
        connection.execute(
            """UPDATE auth_users SET mfa_secret_encrypted = ?, mfa_enabled = 1,
               mfa_recovery_hashes = ?, mfa_pending_secret_encrypted = NULL,
               mfa_last_counter = ?
               WHERE id = ?""",
            (
                row[0],
                json.dumps(recovery_hashes, separators=(",", ":")),
                counter,
                user_id,
            ),
        )
    return recovery_codes


def disable_mfa(user_id: int, password: str, code: str) -> bool:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT password_hash, mfa_secret_encrypted, mfa_recovery_hashes
               FROM auth_users WHERE id = ? AND active = 1 AND mfa_enabled = 1""",
            (user_id,),
        ).fetchone()
        if not row or not verify_password(password, row[0]):
            return False
        if not _consume_second_factor(connection, user_id, code, row[1], row[2]):
            return False
        connection.execute(
            """UPDATE auth_users SET mfa_enabled = 0, mfa_secret_encrypted = NULL,
               mfa_pending_secret_encrypted = NULL, mfa_recovery_hashes = NULL
               , mfa_last_counter = NULL
               WHERE id = ?""",
            (user_id,),
        )
    return True


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


_DUMMY_PASSWORD_HASH = hash_password("aegis-invalid-account-timing-sentinel")


def ensure_bootstrap_admin() -> None:
    username = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    password = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "")
    with get_connection() as connection:
        setup = connection.execute(
            "SELECT state_value FROM application_state WHERE state_key = 'setup_completed'"
        ).fetchone()
        if setup:
            try:
                if json.loads(setup[0]) is True:
                    return
            except (json.JSONDecodeError, TypeError):
                pass
        existing = connection.execute(
            "SELECT id FROM auth_users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            return
        if not password:
            if not os.environ.get("AEGIS_SETUP_TOKEN"):
                return
            password = secrets.token_urlsafe(48)
        connection.execute(
            """INSERT INTO auth_users
               (username, password_hash, role, active, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                username,
                hash_password(password),
                "admin",
                1,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def ensure_development_admin() -> None:
    """Create a real database identity for explicitly unauthenticated local mode."""
    if AUTH_REQUIRED:
        return
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM auth_users WHERE username = ?", (DEVELOPMENT_USERNAME,)
        ).fetchone()
        if existing:
            return
        connection.execute(
            """INSERT INTO auth_users
               (username, password_hash, role, active, created_at)
               VALUES (?, ?, 'admin', 1, ?)""",
            (
                DEVELOPMENT_USERNAME,
                hash_password(secrets.token_urlsafe(32)),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def _development_principal() -> Principal | None:
    try:
        with get_connection() as connection:
            row = connection.execute(
                """SELECT id, username, role, tenant_id FROM auth_users
                   WHERE username = ? AND active = 1""",
                (DEVELOPMENT_USERNAME,),
            ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    return Principal(int(row[0]), row[1], row[2], "", int(row[3]))


def authenticate(username: str, password: str, second_factor: str = "") -> Principal | None:
    now = datetime.now(timezone.utc)
    with get_connection() as connection:
        row = connection.execute(
            """SELECT id, username, password_hash, role, tenant_id,
                      failed_login_count, locked_until, mfa_enabled,
                      mfa_secret_encrypted, mfa_recovery_hashes
               FROM auth_users WHERE username = ? AND active = 1""",
            (username,),
        ).fetchone()
        # Always perform a password derivation to reduce username-enumeration
        # timing differences. Locked users remain locked even with a valid secret.
        password_hash = row[2] if row else _DUMMY_PASSWORD_HASH
        valid_password = verify_password(password, password_hash)
        locked = False
        if row and row[6]:
            try:
                locked = datetime.fromisoformat(row[6]) > now
            except ValueError:
                locked = True
        valid_second_factor = True
        if row and bool(row[7]) and valid_password and not locked:
            valid_second_factor = bool(row[8]) and _consume_second_factor(
                connection, int(row[0]), second_factor, row[8], row[9]
            )
        if not row or not valid_password or not valid_second_factor or locked:
            if row and not locked:
                connection.execute(
                    """UPDATE auth_users
                       SET failed_login_count = COALESCE(failed_login_count, 0) + 1,
                           locked_until = CASE
                               WHEN COALESCE(failed_login_count, 0) + 1 >= ?
                               THEN ?
                               ELSE locked_until
                           END
                       WHERE id = ? AND active = 1
                         AND (locked_until IS NULL OR locked_until <= ?)""",
                    (
                        LOGIN_FAILURE_LIMIT,
                        (now + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)).isoformat(),
                        row[0],
                        now.isoformat(),
                    ),
                )
            return None
        connection.execute(
            """UPDATE auth_users SET failed_login_count = 0, locked_until = NULL,
               last_login_at = ? WHERE id = ?""",
            (now.isoformat(), row[0]),
        )
    return Principal(
        int(row[0]), row[1], row[3], secrets.token_urlsafe(24), int(row[4])
    )


def complete_initial_setup(username: str, password: str, settings: dict) -> Principal:
    bootstrap_username = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, tenant_id FROM auth_users WHERE username = ? AND active = 1",
            (bootstrap_username,),
        ).fetchone()
        if not row:
            raise ValueError("Bootstrap administrator is unavailable.")
        duplicate = connection.execute(
            "SELECT id FROM auth_users WHERE username = ? AND id != ?",
            (username, row[0]),
        ).fetchone()
        if duplicate:
            raise ValueError("That administrator username is already in use.")
        connection.execute(
            """UPDATE auth_users
               SET username = ?, password_hash = ?, role = ?, active = 1
               WHERE id = ?""",
            (username, hash_password(password), "admin", row[0]),
        )
        state_values = {
            "workspace_settings": settings,
            "setup_completed": True,
        }
        for key, value in state_values.items():
            encoded = json.dumps(value, separators=(",", ":"))
            updated = connection.execute(
                """UPDATE application_state
                   SET state_value = ?, updated_at = ? WHERE state_key = ?""",
                (encoded, now, key),
            )
            if not getattr(updated, "rowcount", 0):
                connection.execute(
                    """INSERT INTO application_state (state_key, state_value, updated_at)
                       VALUES (?, ?, ?)""",
                    (key, encoded, now),
                )
    return Principal(
        int(row[0]), username, "admin", secrets.token_urlsafe(24), int(row[1])
    )


def create_session(principal: Principal) -> str:
    token = secrets.token_urlsafe(48)
    token_hash = _session_token_hash(token)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(
        seconds=int(os.environ.get("AEGIS_SESSION_TTL_SECONDS", "28800"))
    )
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ?", (now.isoformat(),)
        )
        connection.execute(
            """INSERT INTO auth_sessions
               (user_id, token_hash, csrf_token, expires_at, created_at, authenticated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                principal.user_id,
                token_hash,
                principal.csrf_token,
                expires_at.isoformat(),
                now.isoformat(),
                now.isoformat(),
            ),
        )
    return token


def _decode_session(token: str) -> Principal | None:
    if not token:
        return None
    token_hash = _session_token_hash(token)
    now = datetime.now(timezone.utc).isoformat()
    try:
        with get_connection() as connection:
            row = connection.execute(
                """SELECT u.id, u.username, u.role, s.csrf_token, u.tenant_id
                   FROM auth_sessions s JOIN auth_users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1""",
                (token_hash, now),
            ).fetchone()
    except Exception:
        return None
    if not row or row[2] not in ROLE_LEVEL:
        return None
    return Principal(int(row[0]), row[1], row[2], row[3], int(row[4]))


def revoke_session(token: str) -> None:
    if not token:
        return
    token_hash = _session_token_hash(token)
    with get_connection() as connection:
        connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))


def revoke_user_sessions(user_id: int) -> None:
    with get_connection() as connection:
        connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))


def session_authentication_is_recent(token: str, max_age_seconds: int | None = None) -> bool:
    """Return whether a live browser session completed authentication recently."""
    if not token:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=max_age_seconds or RECENT_AUTH_SECONDS
    )
    with get_connection() as connection:
        row = connection.execute(
            """SELECT authenticated_at FROM auth_sessions
               WHERE token_hash = ? AND expires_at > ?""",
            (_session_token_hash(token), datetime.now(timezone.utc).isoformat()),
        ).fetchone()
    if not row or not row[0]:
        return False
    try:
        return datetime.fromisoformat(row[0]) >= cutoff
    except ValueError:
        return False


def reauthenticate_session(
    token: str, principal: Principal, password: str, second_factor: str = ""
) -> bool:
    """Reverify a browser session's credentials and refresh its step-up timestamp."""
    if not token or principal.auth_method != "session":
        return False
    verified = authenticate(principal.username, password, second_factor)
    if not verified or verified.user_id != principal.user_id:
        return False
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        updated = connection.execute(
            """UPDATE auth_sessions SET authenticated_at = ?
               WHERE token_hash = ? AND user_id = ? AND expires_at > ?""",
            (now, _session_token_hash(token), principal.user_id, now),
        )
    return bool(getattr(updated, "rowcount", 0))


def _api_token_principal(token: str) -> Principal | None:
    token_hash = hash_api_token(token)
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        row = connection.execute(
            """SELECT u.id, u.username, u.role, u.tenant_id, t.scopes, t.id
               FROM auth_tokens t JOIN auth_users u ON u.id = t.user_id
               WHERE t.hash_scheme = ? AND t.token_hash = ?
               AND t.revoked_at IS NULL AND u.active = 1
               AND (t.expires_at IS NULL OR t.expires_at > ?)""",
            (API_TOKEN_HASH_SCHEME, token_hash, now),
        ).fetchone()
        if row:
            connection.execute(
                "UPDATE auth_tokens SET last_used_at = ? WHERE id = ?", (now, row[5])
            )
    if not row:
        return None
    scopes = tuple(
        scope for scope in str(row[4] or "read").split(",") if scope in TOKEN_SCOPES
    ) or ("read",)
    return Principal(
        int(row[0]), row[1], row[2], "", int(row[3]), scopes, "token"
    )


def _required_token_scope(request: Request) -> str:
    path = request.url.path
    if (
        path.startswith("/api/admin")
        or path.startswith("/api/users")
        or path.startswith("/api/tokens")
        or path in {"/toggle-waf", "/save-waf-rules"}
    ):
        return "admin"
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        return "write"
    return "read"


def _scope_allows(scopes: tuple[str, ...], required: str) -> bool:
    if "*" in scopes or "admin" in scopes:
        return True
    if required == "read" and "write" in scopes:
        return True
    return required in scopes


def principal_from_request(request: Request) -> Principal | None:
    if not AUTH_REQUIRED:
        return _development_principal()
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        return _api_token_principal(authorization[7:].strip())
    legacy = request.headers.get("X-Aegis-Token")
    if legacy:
        return _api_token_principal(legacy)
    session = request.cookies.get(SESSION_COOKIE)
    return _decode_session(session) if session else None


def require_role(minimum_role: str):
    def dependency(request: Request) -> Principal:
        principal = principal_from_request(request)
        if not principal:
            raise HTTPException(status_code=401, detail="Authentication required.")
        if ROLE_LEVEL.get(principal.role, 0) < ROLE_LEVEL[minimum_role]:
            raise HTTPException(status_code=403, detail="Insufficient role.")
        if principal.auth_method == "token":
            required_scope = _required_token_scope(request)
            if not _scope_allows(principal.scopes, required_scope):
                raise HTTPException(
                    status_code=403,
                    detail=f"API token requires the '{required_scope}' scope.",
                )
        if request.method not in {"GET", "HEAD", "OPTIONS"} and principal.csrf_token:
            supplied = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(supplied, principal.csrf_token):
                raise HTTPException(status_code=403, detail="CSRF validation failed.")
        return principal

    return dependency


def websocket_principal(websocket: WebSocket, minimum_role: str) -> Principal | None:
    if not AUTH_REQUIRED:
        return _development_principal()
    session = websocket.cookies.get(SESSION_COOKIE)
    principal = _decode_session(session) if session else None
    if not principal:
        authorization = websocket.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            principal = _api_token_principal(authorization[7:].strip())
    if not principal or ROLE_LEVEL.get(principal.role, 0) < ROLE_LEVEL[minimum_role]:
        return None
    if principal.auth_method == "token" and not _scope_allows(
        principal.scopes, "read"
    ):
        return None
    return principal
