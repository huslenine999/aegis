import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    from database import get_connection
except ImportError:
    from .database import get_connection


GITHUB_API = "https://api.github.com"
WEBHOOK_EVENT_RE = re.compile(r"^[a-z_]{1,64}$")
DELIVERY_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")


def github_enabled() -> bool:
    return bool(
        os.environ.get("AEGIS_GITHUB_CLIENT_ID")
        and os.environ.get("AEGIS_GITHUB_CLIENT_SECRET")
        and os.environ.get("AEGIS_ENCRYPTION_KEY")
    )


def github_webhook_enabled() -> bool:
    return len(os.environ.get("AEGIS_GITHUB_WEBHOOK_SECRET", "")) >= 32


def github_app_enabled() -> bool:
    return bool(
        os.environ.get("AEGIS_GITHUB_APP_ID")
        and (
            os.environ.get("AEGIS_GITHUB_APP_PRIVATE_KEY")
            or os.environ.get("AEGIS_GITHUB_APP_PRIVATE_KEY_B64")
        )
        and github_webhook_enabled()
    )


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def github_app_jwt() -> str:
    """Create the short-lived RS256 JWT required for GitHub App authentication."""
    app_id = os.environ.get("AEGIS_GITHUB_APP_ID", "")
    encoded_key = os.environ.get("AEGIS_GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n")
    if not encoded_key and os.environ.get("AEGIS_GITHUB_APP_PRIVATE_KEY_B64"):
        try:
            encoded_key = base64.b64decode(
                os.environ["AEGIS_GITHUB_APP_PRIVATE_KEY_B64"], validate=True
            ).decode()
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                "AEGIS_GITHUB_APP_PRIVATE_KEY_B64 must encode a PEM private key."
            ) from exc
    if not app_id or not encoded_key:
        raise RuntimeError("GitHub App ID and private key are required.")
    now = int(datetime.now(timezone.utc).timestamp())
    header = _base64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = _base64url(
        json.dumps(
            {"iat": now - 60, "exp": now + 540, "iss": app_id},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode()
    try:
        private_key = serialization.load_pem_private_key(encoded_key.encode(), password=None)
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError("AEGIS_GITHUB_APP_PRIVATE_KEY must be a valid RSA PEM key.") from exc
    return f"{header}.{claims}.{_base64url(signature)}"


def github_installation_token(installation_id: int) -> str:
    if int(installation_id) < 1:
        raise ValueError("GitHub installation ID is invalid.")
    response = requests.post(
        f"{GITHUB_API}/app/installations/{int(installation_id)}/access_tokens",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_app_jwt()}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15,
    )
    response.raise_for_status()
    token = response.json().get("token")
    if not token:
        raise RuntimeError("GitHub did not return an installation token.")
    return str(token)


def _github_app_api(
    method: str, installation_id: int, path: str, payload: dict
) -> dict:
    response = requests.request(
        method,
        f"{GITHUB_API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_installation_token(installation_id)}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json=payload,
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def create_check_run(
    installation_id: int, repository: str, revision: str, details_url: str = ""
) -> int:
    payload = {
        "name": "Aegis security gate",
        "head_sha": revision,
        "status": "in_progress",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "output": {
            "title": "Aegis security scan running",
            "summary": "Aegis is evaluating this pull request for new security findings.",
        },
    }
    if details_url:
        payload["details_url"] = details_url
    result = _github_app_api(
        "POST", installation_id, f"/repos/{repository}/check-runs", payload
    )
    return int(result["id"])


def complete_check_run(
    installation_id: int,
    repository: str,
    check_run_id: int,
    *,
    conclusion: str,
    title: str,
    summary: str,
    details_url: str = "",
    annotations: list[dict] | None = None,
) -> None:
    allowed = {"success", "failure", "neutral", "cancelled", "timed_out", "action_required"}
    if conclusion not in allowed:
        raise ValueError("GitHub check conclusion is invalid.")
    output = {"title": title[:255], "summary": summary[:65000]}
    if annotations:
        output["annotations"] = annotations[:50]
    payload = {
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "output": output,
    }
    if details_url:
        payload["details_url"] = details_url
    _github_app_api(
        "PATCH",
        installation_id,
        f"/repos/{repository}/check-runs/{int(check_run_id)}",
        payload,
    )


def verify_and_record_webhook(
    body: bytes,
    *,
    signature_header: str,
    delivery_id: str,
    event_type: str,
) -> dict:
    """Authenticate a GitHub webhook and atomically reject replayed deliveries."""
    secret = os.environ.get("AEGIS_GITHUB_WEBHOOK_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("GitHub webhook processing is not configured.")
    if not signature_header.startswith("sha256="):
        raise ValueError("GitHub webhook signature is missing or invalid.")
    supplied = signature_header.removeprefix("sha256=")
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if len(supplied) != 64 or not hmac.compare_digest(supplied, expected):
        raise ValueError("GitHub webhook signature is missing or invalid.")
    if not DELIVERY_ID_RE.fullmatch(delivery_id or ""):
        raise ValueError("GitHub delivery identifier is invalid.")
    if not WEBHOOK_EVENT_RE.fullmatch(event_type or ""):
        raise ValueError("GitHub event type is invalid.")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("GitHub webhook body must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("GitHub webhook body must be a JSON object.")
    repository = payload.get("repository") or {}
    repository_name = str(repository.get("full_name") or "")[:255]
    if repository_name and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository_name):
        raise ValueError("GitHub repository identity is invalid.")
    digest = hashlib.sha256(body).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        existing = connection.execute(
            """SELECT payload_sha256, status FROM github_webhook_deliveries
               WHERE delivery_id = ?""",
            (delivery_id,),
        ).fetchone()
        if existing:
            if existing[0] != digest or existing[1] != "failed":
                raise ValueError("GitHub webhook delivery has already been processed.")
            connection.execute(
                """UPDATE github_webhook_deliveries
                   SET status = 'accepted', processed_at = NULL WHERE delivery_id = ?""",
                (delivery_id,),
            )
        else:
            connection.execute(
                """INSERT INTO github_webhook_deliveries
                   (delivery_id, event_type, repository, received_at, payload_sha256,
                    status, processed_at)
                   VALUES (?, ?, ?, ?, ?, ?, NULL)""",
                (
                    delivery_id,
                    event_type,
                    repository_name,
                    now,
                    digest,
                    "accepted",
                ),
            )
    return {
        "delivery_id": delivery_id,
        "event_type": event_type,
        "repository": repository_name,
        "payload_sha256": digest,
        "action": str(payload.get("action") or "")[:64],
        "installation_id": int((payload.get("installation") or {}).get("id") or 0),
        "pull_request": int((payload.get("pull_request") or {}).get("number") or 0),
        "head_sha": str(
            ((payload.get("pull_request") or {}).get("head") or {}).get("sha") or ""
        )[:64],
        "head_ref": str(
            ((payload.get("pull_request") or {}).get("head") or {}).get("ref") or ""
        )[:255],
    }


def mark_webhook_delivery(
    delivery_id: str, status: str, scan_run_id: int | None = None
) -> None:
    if status not in {"processed", "ignored", "failed"}:
        raise ValueError("GitHub webhook delivery status is invalid.")
    with get_connection() as connection:
        connection.execute(
            """UPDATE github_webhook_deliveries SET status = ?, processed_at = ?,
               scan_run_id = COALESCE(?, scan_run_id)
               WHERE delivery_id = ?""",
            (
                status,
                datetime.now(timezone.utc).isoformat(),
                scan_run_id,
                delivery_id,
            ),
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
