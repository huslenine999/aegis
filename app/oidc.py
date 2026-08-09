import base64
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse

import requests
from cryptography.fernet import Fernet

from .auth import Principal
from .database import USING_POSTGRES, get_connection


def oidc_enabled() -> bool:
    return bool(os.environ.get("AEGIS_OIDC_ISSUER") and os.environ.get("AEGIS_OIDC_CLIENT_ID"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fernet() -> Fernet:
    try:
        return Fernet(os.environ.get("AEGIS_ENCRYPTION_KEY", "").encode())
    except (TypeError, ValueError) as exc:
        raise RuntimeError("AEGIS_ENCRYPTION_KEY is required for OIDC.") from exc


def _discovery() -> dict:
    issuer = os.environ.get("AEGIS_OIDC_ISSUER", "").rstrip("/")
    parsed = urlparse(issuer)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("AEGIS_OIDC_ISSUER must be an HTTPS issuer URL.")
    response = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    response.raise_for_status()
    metadata = response.json()
    if str(metadata.get("issuer", "")).rstrip("/") != issuer:
        raise RuntimeError("OIDC discovery issuer does not match configuration.")
    return metadata


def begin_oidc(callback_url: str, return_to: str = "/") -> str:
    if not oidc_enabled():
        raise RuntimeError("OIDC is not configured.")
    if not return_to.startswith("/") or return_to.startswith("//"):
        return_to = "/"
    metadata = _discovery()
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    nonce = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    with get_connection() as connection:
        connection.execute("DELETE FROM oidc_states WHERE expires_at < ?", (_now(),))
        connection.execute(
            """INSERT INTO oidc_states
               (state_hash, verifier_encrypted, nonce, return_to, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                hashlib.sha256(state.encode()).hexdigest(),
                _fernet().encrypt(verifier.encode()).decode(),
                nonce,
                return_to,
                expires,
            ),
        )
    return str(metadata["authorization_endpoint"]) + "?" + urlencode(
        {
            "response_type": "code",
            "client_id": os.environ["AEGIS_OIDC_CLIENT_ID"],
            "redirect_uri": callback_url,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )


def _mapped_role(claims: dict) -> str:
    claim_name = os.environ.get("AEGIS_OIDC_ROLE_CLAIM", "roles")
    values = claims.get(claim_name, [])
    values = [values] if isinstance(values, str) else list(values or [])
    try:
        mapping = json.loads(os.environ.get("AEGIS_OIDC_ROLE_MAPPING", "") or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("AEGIS_OIDC_ROLE_MAPPING must be valid JSON.") from exc
    mapped = {str(mapping.get(value, "viewer")) for value in values}
    return "admin" if "admin" in mapped else "operator" if "operator" in mapped else "viewer"


def complete_oidc(code: str, state: str, callback_url: str) -> tuple[Principal, str]:
    metadata = _discovery()
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    with get_connection() as connection:
        row = connection.execute(
            """SELECT verifier_encrypted, nonce, return_to, expires_at
               FROM oidc_states WHERE state_hash = ?""",
            (state_hash,),
        ).fetchone()
        connection.execute("DELETE FROM oidc_states WHERE state_hash = ?", (state_hash,))
    if not row or row[3] < _now():
        raise ValueError("OIDC state is invalid or expired.")
    verifier = _fernet().decrypt(row[0].encode()).decode()
    token_response = requests.post(
        metadata["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": os.environ["AEGIS_OIDC_CLIENT_ID"],
            "client_secret": os.environ.get("AEGIS_OIDC_CLIENT_SECRET", ""),
            "code_verifier": verifier,
        },
        timeout=15,
    )
    token_response.raise_for_status()
    id_token = token_response.json().get("id_token")
    if not id_token:
        raise ValueError("Identity provider did not return an ID token.")
    try:
        import jwt
    except ImportError as exc:
        raise RuntimeError("The PyJWT runtime dependency is required for OIDC.") from exc
    signing_key = jwt.PyJWKClient(metadata["jwks_uri"]).get_signing_key_from_jwt(id_token).key
    provider_algorithms = set(
        metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
    )
    algorithms = sorted(
        provider_algorithms
        & {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
    )
    if not algorithms:
        raise ValueError("OIDC provider does not advertise a supported signing algorithm.")
    claims = jwt.decode(
        id_token,
        signing_key,
        algorithms=algorithms,
        audience=os.environ["AEGIS_OIDC_CLIENT_ID"],
        issuer=os.environ["AEGIS_OIDC_ISSUER"].rstrip("/"),
    )
    if not secrets.compare_digest(str(claims.get("nonce", "")), str(row[1])):
        raise ValueError("OIDC nonce validation failed.")
    subject = str(claims.get("sub") or "")
    if not subject:
        raise ValueError("OIDC subject is missing.")
    issuer = os.environ["AEGIS_OIDC_ISSUER"].rstrip("/")
    tenant_id = int(os.environ.get("AEGIS_OIDC_TENANT_ID", "1"))
    role = _mapped_role(claims)
    preferred = str(claims.get("preferred_username") or claims.get("email") or "")[:128]
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,128}", preferred):
        preferred = "oidc-" + hashlib.sha256(f"{issuer}:{subject}".encode()).hexdigest()[:20]
    with get_connection() as connection:
        identity = connection.execute(
            """SELECT u.id, u.username, u.role, u.tenant_id, u.active
               FROM oidc_identities i JOIN auth_users u ON u.id = i.user_id
               WHERE i.issuer = ? AND i.subject = ?""",
            (issuer, subject),
        ).fetchone()
        if identity:
            if not identity[4]:
                raise ValueError("OIDC account is disabled.")
            user_id, preferred, role, tenant_id = int(identity[0]), identity[1], identity[2], int(identity[3])
            connection.execute(
                "UPDATE oidc_identities SET last_login_at = ? WHERE issuer = ? AND subject = ?",
                (_now(), issuer, subject),
            )
        else:
            if os.environ.get("AEGIS_OIDC_AUTO_PROVISION", "false").lower() not in {"1", "true", "yes", "on"}:
                raise ValueError("OIDC account is not provisioned.")
            insert = """INSERT INTO auth_users
                (tenant_id, username, password_hash, role, active, created_at)
                VALUES (?, ?, ?, ?, 1, ?)"""
            if USING_POSTGRES:
                insert += " RETURNING id"
            cursor = connection.execute(insert, (tenant_id, preferred, "!oidc", role, _now()))
            user_id = int(cursor.fetchone()[0]) if USING_POSTGRES else int(cursor.lastrowid)
            connection.execute(
                """INSERT INTO oidc_identities
                   (issuer, subject, user_id, created_at, last_login_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (issuer, subject, user_id, _now(), _now()),
            )
    return Principal(user_id, preferred, role, secrets.token_urlsafe(24), tenant_id), str(row[2])
