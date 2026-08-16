import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote, urlencode, urlparse

import requests
from cryptography.fernet import Fernet, InvalidToken

from .auth import Principal
from .database import USING_POSTGRES, get_connection


OIDC_BINDING_COOKIE = "aegis_oidc_binding"
OIDC_TRANSACTION_TTL_SECONDS = 10 * 60
DISCOVERY_CACHE_MAX_ENTRIES = 16
DISCOVERY_CACHE_TTL_SECONDS = 5 * 60
JWKS_CACHE_MAX_ENTRIES = 16
JWKS_CACHE_TTL_SECONDS = 5 * 60
MAX_PROVIDER_METADATA_BYTES = 64 * 1024
MAX_JWKS_BYTES = 256 * 1024
SUPPORTED_ID_TOKEN_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)
_DISCOVERY_CACHE: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_JWKS_CACHE: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_CACHE_LOCK = threading.RLock()


def oidc_enabled() -> bool:
    return bool(
        os.environ.get("AEGIS_OIDC_ISSUER")
        and os.environ.get("AEGIS_OIDC_CLIENT_ID")
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fernet() -> Fernet:
    try:
        return Fernet(os.environ.get("AEGIS_ENCRYPTION_KEY", "").encode())
    except (TypeError, ValueError) as exc:
        raise RuntimeError("AEGIS_ENCRYPTION_KEY is required for OIDC.") from exc


def _clear_caches() -> None:
    with _CACHE_LOCK:
        _DISCOVERY_CACHE.clear()
        _JWKS_CACHE.clear()


def _cache_get(
    cache: OrderedDict[str, tuple[float, dict[str, Any]]],
    key: str,
) -> dict[str, Any] | None:
    now = time.monotonic()
    with _CACHE_LOCK:
        entry = cache.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at <= now:
            cache.pop(key, None)
            return None
        cache.move_to_end(key)
        return dict(value)


def _cache_put(
    cache: OrderedDict[str, tuple[float, dict[str, Any]]],
    key: str,
    value: dict[str, Any],
    ttl: int,
    maximum: int,
) -> None:
    with _CACHE_LOCK:
        cache[key] = (time.monotonic() + ttl, dict(value))
        cache.move_to_end(key)
        while len(cache) > maximum:
            cache.popitem(last=False)


def new_browser_binding() -> str:
    return secrets.token_urlsafe(32)


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


def _hash_binding(binding: str) -> str:
    return hashlib.sha256(binding.encode()).hexdigest()


def _safe_return_to(value: Any) -> str:
    """Keep post-login redirects on this origin, including browser edge cases."""
    if not isinstance(value, str) or not value.startswith("/"):
        return "/"
    decoded = unquote(unquote(value))
    if decoded.startswith("//") or "\\" in decoded or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in decoded
    ):
        return "/"
    parsed = urlparse(decoded)
    if parsed.scheme or parsed.netloc:
        return "/"
    return value


def _safe_host(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    if normalized in {"localhost", "localhost.localdomain"} or normalized.endswith(
        (".localhost", ".local", ".internal")
    ):
        return False
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return True
    return address.is_global


def _normalized_https_url(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"OIDC {label} must be an approved HTTPS URL.")
    text = value.strip()
    if not text or len(text) > 2048:
        raise ValueError(f"OIDC {label} must be an approved HTTPS URL.")
    parsed = urlparse(text)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"OIDC {label} must be an approved HTTPS URL.") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or not _safe_host(parsed.hostname)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(f"OIDC {label} must be an approved HTTPS URL.")
    return text.rstrip("/") if text.endswith("/") and parsed.path == "/" else text


def _origin(value: str) -> str:
    parsed = urlparse(value)
    host = str(parsed.hostname or "").lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parsed.port
    if port in (None, 443):
        return f"https://{host}"
    return f"https://{host}:{port}"


def _approved_origins(issuer: str) -> set[str]:
    origins = {_origin(issuer)}
    configured = os.environ.get("AEGIS_OIDC_ALLOWED_ORIGINS", "")
    for raw_origin in configured.split(","):
        raw_origin = raw_origin.strip()
        if not raw_origin:
            continue
        normalized = _normalized_https_url(raw_origin, "allowed origin")
        parsed = urlparse(normalized)
        if parsed.path not in {"", "/"}:
            raise ValueError("OIDC allowed origins must not include a path.")
        origins.add(_origin(normalized))
    return origins


def _validate_endpoint(value: Any, label: str, issuer: str) -> str:
    endpoint = _normalized_https_url(value, label)
    if _origin(endpoint) not in _approved_origins(issuer):
        raise ValueError(f"OIDC {label} must use an approved HTTPS origin.")
    return endpoint


def _validate_provider_metadata(metadata: Any, issuer: str) -> dict[str, Any]:
    configured_issuer = _normalized_https_url(issuer, "issuer").rstrip("/")
    if not isinstance(metadata, dict):
        raise ValueError("OIDC discovery metadata must be an object.")
    reported_issuer = str(metadata.get("issuer", "")).rstrip("/")
    if reported_issuer != configured_issuer:
        raise ValueError("OIDC discovery issuer does not match configuration.")

    snapshot: dict[str, Any] = {
        "issuer": configured_issuer,
        "authorization_endpoint": _validate_endpoint(
            metadata.get("authorization_endpoint"), "authorization endpoint", configured_issuer
        ),
        "token_endpoint": _validate_endpoint(
            metadata.get("token_endpoint"), "token endpoint", configured_issuer
        ),
        "jwks_uri": _validate_endpoint(
            metadata.get("jwks_uri"), "JWKS endpoint", configured_issuer
        ),
    }
    advertised = metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
    if isinstance(advertised, str):
        advertised = [advertised]
    if not isinstance(advertised, (list, tuple)):
        raise ValueError("OIDC signing algorithm metadata is invalid.")
    algorithms = sorted(
        {str(value) for value in advertised} & SUPPORTED_ID_TOKEN_ALGORITHMS
    )
    if not algorithms:
        raise ValueError("OIDC provider does not advertise a supported signing algorithm.")
    snapshot["id_token_signing_alg_values_supported"] = algorithms
    return snapshot


def _discovery(issuer: str | None = None) -> dict[str, Any]:
    configured_issuer = _normalized_https_url(
        issuer or os.environ.get("AEGIS_OIDC_ISSUER", ""), "issuer"
    ).rstrip("/")
    cache_key = configured_issuer + "|" + ",".join(
        sorted(_approved_origins(configured_issuer))
    )
    cached = _cache_get(_DISCOVERY_CACHE, cache_key)
    if cached is not None:
        return cached

    response = requests.get(
        f"{configured_issuer}/.well-known/openid-configuration",
        timeout=10,
        allow_redirects=False,
    )
    status_code = int(getattr(response, "status_code", 200))
    if 300 <= status_code < 400:
        raise RuntimeError("OIDC discovery redirects are not allowed.")
    response.raise_for_status()
    try:
        metadata = response.json()
    except (TypeError, ValueError) as exc:
        raise RuntimeError("OIDC discovery metadata is not valid JSON.") from exc
    try:
        encoded_size = len(json.dumps(metadata, separators=(",", ":")).encode())
    except (TypeError, ValueError) as exc:
        raise RuntimeError("OIDC discovery metadata is not valid JSON.") from exc
    if encoded_size > MAX_PROVIDER_METADATA_BYTES:
        raise RuntimeError("OIDC discovery metadata is too large.")
    validated = _validate_provider_metadata(metadata, configured_issuer)
    _cache_put(
        _DISCOVERY_CACHE,
        cache_key,
        validated,
        DISCOVERY_CACHE_TTL_SECONDS,
        DISCOVERY_CACHE_MAX_ENTRIES,
    )
    return dict(validated)


def begin_oidc(
    callback_url: str,
    return_to: str = "/",
    *,
    browser_binding: str | None = None,
) -> str:
    if not oidc_enabled():
        raise RuntimeError("OIDC is not configured.")
    if not isinstance(callback_url, str) or not callback_url or len(callback_url) > 2048:
        raise ValueError("OIDC callback URL is invalid.")
    return_to = _safe_return_to(return_to)
    binding = browser_binding or new_browser_binding()
    if not isinstance(binding, str) or not 16 <= len(binding) <= 256:
        raise ValueError("OIDC browser binding is invalid.")

    issuer = _normalized_https_url(os.environ["AEGIS_OIDC_ISSUER"], "issuer").rstrip("/")
    metadata = _validate_provider_metadata(_discovery(issuer), issuer)
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    nonce = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    expires = (
        datetime.now(timezone.utc) + timedelta(seconds=OIDC_TRANSACTION_TTL_SECONDS)
    ).isoformat()
    metadata_blob = json.dumps(metadata, separators=(",", ":"))
    if len(metadata_blob.encode()) > MAX_PROVIDER_METADATA_BYTES:
        raise RuntimeError("OIDC provider metadata is too large.")
    with get_connection() as connection:
        connection.execute("DELETE FROM oidc_states WHERE expires_at < ?", (_now(),))
        connection.execute(
            """INSERT INTO oidc_states
               (state_hash, verifier_encrypted, nonce, return_to, expires_at,
                browser_binding_hash, provider_metadata_encrypted, issuer,
                client_id, redirect_uri)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _state_hash(state),
                _fernet().encrypt(verifier.encode()).decode(),
                nonce,
                return_to,
                expires,
                _hash_binding(binding),
                _fernet().encrypt(metadata_blob.encode()).decode(),
                issuer,
                os.environ["AEGIS_OIDC_CLIENT_ID"],
                callback_url,
            ),
        )
    authorization_endpoint = str(metadata["authorization_endpoint"])
    separator = "&" if "?" in authorization_endpoint else "?"
    return authorization_endpoint + separator + urlencode(
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


def _reserve_oidc_state(
    state: str,
    browser_binding: str,
    callback_url: str,
) -> dict[str, Any]:
    if (
        not isinstance(state, str)
        or not state
        or len(state) > 512
        or not isinstance(browser_binding, str)
        or not browser_binding
        or len(browser_binding) > 256
        or not isinstance(callback_url, str)
        or not callback_url
    ):
        raise ValueError("OIDC state is invalid or expired.")
    state_hash = _state_hash(state)
    binding_hash = _hash_binding(browser_binding)
    now = _now()
    reserved_at = now
    with get_connection() as connection:
        updated = connection.execute(
            """UPDATE oidc_states
               SET reserved_at = ?
               WHERE state_hash = ?
                 AND browser_binding_hash = ?
                 AND redirect_uri = ?
                 AND expires_at >= ?
                 AND reserved_at IS NULL""",
            (reserved_at, state_hash, binding_hash, callback_url, now),
        )
        if getattr(updated, "rowcount", 0) != 1:
            raise ValueError("OIDC state is invalid or expired.")
        row = connection.execute(
            """SELECT verifier_encrypted, nonce, return_to, expires_at,
                      provider_metadata_encrypted, issuer, client_id
                 FROM oidc_states WHERE state_hash = ?""",
            (state_hash,),
        ).fetchone()
    if not row or not row[4] or not row[5] or not row[6]:
        raise ValueError("OIDC state is invalid or expired.")
    return {
        "verifier_encrypted": row[0],
        "nonce": row[1],
        "return_to": row[2],
        "expires_at": row[3],
        "provider_metadata_encrypted": row[4],
        "issuer": row[5],
        "client_id": row[6],
    }


def _response_json(response: Any, *, label: str, maximum: int) -> dict[str, Any]:
    status_code = int(getattr(response, "status_code", 200))
    if 300 <= status_code < 400:
        raise RuntimeError(f"OIDC {label} redirects are not allowed.")
    response.raise_for_status()
    content = getattr(response, "content", None)
    if content is not None and len(content) > maximum:
        raise RuntimeError(f"OIDC {label} response is too large.")
    try:
        payload = response.json()
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"OIDC {label} response is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"OIDC {label} response is invalid.")
    return payload


def _exchange_code(
    code: str,
    callback_url: str,
    metadata: dict[str, Any],
    verifier: str,
    client_id: str,
) -> str:
    if not isinstance(code, str) or not code or len(code) > 4096:
        raise ValueError("OIDC authorization code is invalid.")
    token_response = requests.post(
        metadata["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": client_id,
            "client_secret": os.environ.get("AEGIS_OIDC_CLIENT_SECRET", ""),
            "code_verifier": verifier,
        },
        timeout=15,
        allow_redirects=False,
    )
    payload = _response_json(token_response, label="token", maximum=MAX_PROVIDER_METADATA_BYTES)
    id_token = payload.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise ValueError("Identity provider did not return an ID token.")
    return id_token


def _jwks(metadata: dict[str, Any]) -> dict[str, Any]:
    uri = str(metadata["jwks_uri"])
    cached = _cache_get(_JWKS_CACHE, uri)
    if cached is not None:
        return cached
    response = requests.get(uri, timeout=10, allow_redirects=False)
    payload = _response_json(response, label="JWKS", maximum=MAX_JWKS_BYTES)
    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 64:
        raise RuntimeError("OIDC JWKS response is invalid.")
    _cache_put(_JWKS_CACHE, uri, payload, JWKS_CACHE_TTL_SECONDS, JWKS_CACHE_MAX_ENTRIES)
    return dict(payload)


def _verify_id_token(
    id_token: str,
    metadata: dict[str, Any],
    client_id: str,
) -> dict[str, Any]:
    try:
        import jwt
    except ImportError as exc:
        raise RuntimeError("The PyJWT runtime dependency is required for OIDC.") from exc

    algorithms = list(metadata["id_token_signing_alg_values_supported"])
    header = jwt.get_unverified_header(id_token)
    algorithm = header.get("alg")
    if algorithm not in algorithms:
        raise ValueError("OIDC ID token uses an unsupported signing algorithm.")
    key_set = jwt.PyJWKSet.from_dict(_jwks(metadata))
    key_id = header.get("kid")
    try:
        signing_key = key_set[key_id] if key_id else next(iter(key_set))
    except (KeyError, StopIteration) as exc:
        raise ValueError("OIDC signing key was not found.") from exc
    if signing_key.algorithm_name not in algorithms:
        raise ValueError("OIDC signing key uses an unsupported algorithm.")
    return jwt.decode(
        id_token,
        signing_key.key,
        algorithms=algorithms,
        audience=client_id,
        issuer=metadata["issuer"],
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


def complete_oidc(
    code: str,
    state: str,
    callback_url: str,
    *,
    browser_binding: str | None = None,
) -> tuple[Principal, str]:
    if not browser_binding:
        raise ValueError("OIDC state is invalid or expired.")
    # This reservation is the transaction boundary: the browser binding,
    # callback URL, expiry, and one-time-use bit are checked before any network.
    row = _reserve_oidc_state(state, browser_binding, callback_url)
    try:
        metadata = _validate_provider_metadata(
            json.loads(_fernet().decrypt(row["provider_metadata_encrypted"].encode())),
            row["issuer"],
        )
        verifier = _fernet().decrypt(row["verifier_encrypted"].encode()).decode()
    except (InvalidToken, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("OIDC state is invalid or expired.") from exc

    id_token = _exchange_code(
        code,
        callback_url,
        metadata,
        verifier,
        row["client_id"],
    )
    claims = _verify_id_token(id_token, metadata, row["client_id"])
    if not isinstance(claims, dict):
        raise ValueError("OIDC ID token claims are invalid.")
    if not secrets.compare_digest(str(claims.get("nonce", "")), str(row["nonce"])):
        raise ValueError("OIDC nonce validation failed.")
    subject = str(claims.get("sub") or "")
    if not subject:
        raise ValueError("OIDC subject is missing.")
    issuer = str(metadata["issuer"])
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
            user_id, preferred, role, tenant_id = (
                int(identity[0]),
                identity[1],
                identity[2],
                int(identity[3]),
            )
            connection.execute(
                "UPDATE oidc_identities SET last_login_at = ? WHERE issuer = ? AND subject = ?",
                (_now(), issuer, subject),
            )
        else:
            if os.environ.get("AEGIS_OIDC_AUTO_PROVISION", "false").lower() not in {
                "1",
                "true",
                "yes",
                "on",
            }:
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
    return Principal(user_id, preferred, role, secrets.token_urlsafe(24), tenant_id), str(
        row["return_to"]
    )
