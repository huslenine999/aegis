import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import requests
from cryptography.fernet import Fernet, InvalidToken

try:
    from database import get_connection
except ImportError:
    from .database import get_connection


GITHUB_API = "https://api.github.com"


def github_enabled() -> bool:
    return bool(
        os.environ.get("AEGIS_GITHUB_CLIENT_ID")
        and os.environ.get("AEGIS_GITHUB_CLIENT_SECRET")
        and os.environ.get("AEGIS_ENCRYPTION_KEY")
    )


def _fernet() -> Fernet:
    key = os.environ.get("AEGIS_ENCRYPTION_KEY", "")
    if not key:
        raise RuntimeError("AEGIS_ENCRYPTION_KEY is not configured.")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("AEGIS_ENCRYPTION_KEY must be a Fernet key.") from exc


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Stored GitHub credential could not be decrypted.") from exc


def begin_oauth(user_id: int, callback_url: str) -> str:
    if not github_enabled():
        raise RuntimeError("GitHub integration is not configured.")
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM github_oauth_states WHERE user_id = ?", (user_id,)
        )
        connection.execute(
            """INSERT INTO github_oauth_states
               (state_hash, user_id, verifier_encrypted, expires_at)
               VALUES (?, ?, ?, ?)""",
            (state_hash, user_id, _encrypt(verifier), expires_at),
        )
    query = urlencode(
        {
            "client_id": os.environ["AEGIS_GITHUB_CLIENT_ID"],
            "redirect_uri": callback_url,
            "scope": "repo read:user",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"https://github.com/login/oauth/authorize?{query}"


def complete_oauth(code: str, state: str, callback_url: str) -> int:
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    with get_connection() as connection:
        row = connection.execute(
            """SELECT user_id, verifier_encrypted, expires_at
               FROM github_oauth_states WHERE state_hash = ?""",
            (state_hash,),
        ).fetchone()
        connection.execute(
            "DELETE FROM github_oauth_states WHERE state_hash = ?", (state_hash,)
        )
    if not row or row[2] < datetime.now(timezone.utc).isoformat():
        raise ValueError("GitHub authorization state is invalid or expired.")
    verifier = _decrypt(row[1])
    response = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": os.environ["AEGIS_GITHUB_CLIENT_ID"],
            "client_secret": os.environ["AEGIS_GITHUB_CLIENT_SECRET"],
            "code": code,
            "redirect_uri": callback_url,
            "code_verifier": verifier,
        },
        timeout=15,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise ValueError(payload.get("error_description") or "GitHub did not return an access token.")
    profile = _github_get(token, "/user")
    user_id = int(row[0])
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM github_connections WHERE user_id = ?", (user_id,)
        )
        connection.execute(
            """INSERT INTO github_connections
               (user_id, github_login, token_encrypted, scopes, connected_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                user_id,
                profile["login"],
                _encrypt(token),
                payload.get("scope", ""),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return user_id


def _github_get(token: str, path: str, params: dict | None = None):
    response = requests.get(
        f"{GITHUB_API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        params=params,
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def github_connection(user_id: int) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT github_login, scopes, connected_at FROM github_connections WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        return None
    return {"login": row[0], "scopes": row[1], "connected_at": row[2]}


def github_token(user_id: int) -> str | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT token_encrypted FROM github_connections WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return _decrypt(row[0]) if row else None


def list_repositories(user_id: int, page: int = 1) -> list[dict]:
    token = github_token(user_id)
    if not token:
        raise ValueError("GitHub is not connected.")
    repos = _github_get(
        token,
        "/user/repos",
        {
            "affiliation": "owner,collaborator,organization_member",
            "sort": "updated",
            "per_page": 100,
            "page": max(1, page),
        },
    )
    return [
        {
            "id": int(repo["id"]),
            "full_name": repo["full_name"],
            "name": repo["name"],
            "private": bool(repo["private"]),
            "clone_url": repo["clone_url"],
            "default_branch": repo.get("default_branch") or "main",
            "updated_at": repo.get("updated_at"),
        }
        for repo in repos
    ]


def disconnect_github(user_id: int) -> None:
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM github_connections WHERE user_id = ?", (user_id,)
        )
