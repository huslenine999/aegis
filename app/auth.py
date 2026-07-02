import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, Request, WebSocket

try:
    from database import get_connection
except ImportError:
    from .database import get_connection


SESSION_COOKIE = "aegis_session"
ROLE_LEVEL = {"viewer": 10, "operator": 20, "admin": 30}
AUTH_REQUIRED = os.environ.get("AEGIS_REQUIRE_AUTH", "").lower() in {"1", "true", "yes", "on"} or (
    os.environ.get("AEGIS_ENV", "development").lower() == "production"
)


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    role: str
    csrf_token: str


def _secret() -> bytes:
    value = os.environ.get("AEGIS_SESSION_SECRET", "")
    if not value and not AUTH_REQUIRED:
        value = "development-session-secret-not-for-production"
    return value.encode()


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


def ensure_bootstrap_admin() -> None:
    username = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    password = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "")
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM auth_users WHERE username = ?", (username,)
        ).fetchone()
        if existing or not password:
            return
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


def authenticate(username: str, password: str) -> Principal | None:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT id, username, password_hash, role
               FROM auth_users WHERE username = ? AND active = 1""",
            (username,),
        ).fetchone()
    if not row or not verify_password(password, row[2]):
        return None
    return Principal(int(row[0]), row[1], row[3], secrets.token_urlsafe(24))


def complete_initial_setup(username: str, password: str, settings: dict) -> Principal:
    bootstrap_username = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id FROM auth_users WHERE username = ? AND active = 1",
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
    return Principal(int(row[0]), username, "admin", secrets.token_urlsafe(24))


def create_session(principal: Principal) -> str:
    payload = {
        "sub": principal.user_id,
        "usr": principal.username,
        "role": principal.role,
        "csrf": principal.csrf_token,
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=")
    signature = hmac.new(_secret(), raw, hashlib.sha256).digest()
    return f"{raw.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def _decode_session(token: str) -> Principal | None:
    try:
        raw_text, signature_text = token.split(".", 1)
        raw = raw_text.encode()
        signature = base64.urlsafe_b64decode(signature_text + "==")
        expected = hmac.new(_secret(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(raw_text + "=="))
        age = int(datetime.now(timezone.utc).timestamp()) - int(payload["iat"])
        if age < 0 or age > int(os.environ.get("AEGIS_SESSION_TTL_SECONDS", "28800")):
            return None
        if payload["role"] not in ROLE_LEVEL:
            return None
        return Principal(
            int(payload["sub"]), payload["usr"], payload["role"], payload["csrf"]
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _api_token_principal(token: str) -> Principal | None:
    legacy = os.environ.get("AEGIS_ADMIN_TOKEN", "")
    if legacy and hmac.compare_digest(token, legacy):
        return Principal(0, "service-admin", "admin", "")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        row = connection.execute(
            """SELECT u.id, u.username, u.role
               FROM auth_tokens t JOIN auth_users u ON u.id = t.user_id
               WHERE t.token_hash = ? AND u.active = 1
               AND (t.expires_at IS NULL OR t.expires_at > ?)""",
            (token_hash, now),
        ).fetchone()
    if not row:
        return None
    return Principal(int(row[0]), row[1], row[2], "")


def principal_from_request(request: Request) -> Principal | None:
    if not AUTH_REQUIRED:
        return Principal(0, "development", "admin", "")
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
        if request.method not in {"GET", "HEAD", "OPTIONS"} and principal.csrf_token:
            supplied = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(supplied, principal.csrf_token):
                raise HTTPException(status_code=403, detail="CSRF validation failed.")
        return principal

    return dependency


def websocket_principal(websocket: WebSocket, minimum_role: str) -> Principal | None:
    if not AUTH_REQUIRED:
        return Principal(0, "development", "admin", "")
    session = websocket.cookies.get(SESSION_COOKIE)
    principal = _decode_session(session) if session else None
    if not principal:
        authorization = websocket.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            principal = _api_token_principal(authorization[7:].strip())
    if not principal or ROLE_LEVEL.get(principal.role, 0) < ROLE_LEVEL[minimum_role]:
        return None
    return principal
