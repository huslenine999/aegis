import base64
import json
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import database, oidc


CALLBACK_URL = "https://aegis.example.com/api/auth/oidc/callback"
ISSUER = "https://idp.example.com/tenant"


def _metadata(issuer: str = ISSUER) -> dict:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def _configure(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "oidc.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(oidc, "get_connection", database.get_connection)
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("AEGIS_OIDC_CLIENT_ID", "client-id")
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    database.initialize_database(reset=True)
    oidc._clear_caches()


def test_oidc_transaction_is_browser_bound_and_reserved_once(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)
    monkeypatch.setattr(oidc, "_discovery", lambda issuer=None: _metadata(issuer or ISSUER))

    binding = oidc.new_browser_binding()
    authorization_url = oidc.begin_oidc(CALLBACK_URL, browser_binding=binding)
    state = dict(
        item.split("=", 1)
        for item in urlparse(authorization_url).query.split("&")
        if item.startswith("state=")
    )["state"]

    with database.get_connection() as connection:
        row = connection.execute(
            """SELECT browser_binding_hash, provider_metadata_encrypted,
                      redirect_uri, reserved_at
                 FROM oidc_states WHERE state_hash = ?""",
            (oidc._state_hash(state),),
        ).fetchone()
    assert row[0] == oidc._hash_binding(binding)
    assert json.loads(oidc._fernet().decrypt(row[1].encode()))["issuer"] == ISSUER
    assert row[2] == CALLBACK_URL
    assert row[3] is None

    reserved = oidc._reserve_oidc_state(state, binding, CALLBACK_URL)
    assert reserved["issuer"] == ISSUER
    with pytest.raises(ValueError, match="invalid or expired"):
        oidc._reserve_oidc_state(state, binding, CALLBACK_URL)


def test_oidc_callback_rejects_wrong_browser_binding_before_network(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)
    monkeypatch.setattr(oidc, "_discovery", lambda issuer=None: _metadata(issuer or ISSUER))
    binding = oidc.new_browser_binding()
    authorization_url = oidc.begin_oidc(CALLBACK_URL, browser_binding=binding)
    query = parse_qs(urlparse(authorization_url).query)
    state = query["state"][0]

    def unexpected_network(*args, **kwargs):
        raise AssertionError("callback performed outbound work before binding validation")

    monkeypatch.setattr(oidc.requests, "post", unexpected_network)
    with pytest.raises(ValueError, match="invalid or expired"):
        oidc.complete_oidc("code", state, CALLBACK_URL, browser_binding="wrong-binding")


def test_oidc_callback_uses_the_stored_snapshot_without_rediscovery(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)
    discovery_calls = []

    def discover(issuer=None):
        discovery_calls.append(issuer)
        return _metadata(issuer or ISSUER)

    monkeypatch.setattr(oidc, "_discovery", discover)
    binding = oidc.new_browser_binding()
    authorization_url = oidc.begin_oidc(CALLBACK_URL, browser_binding=binding)
    query = parse_qs(urlparse(authorization_url).query)
    state = query["state"][0]
    nonce = query["nonce"][0]
    monkeypatch.setenv("AEGIS_OIDC_AUTO_PROVISION", "true")
    monkeypatch.setattr(
        oidc,
        "_discovery",
        lambda issuer=None: (_ for _ in ()).throw(
            AssertionError("OIDC callback rediscovered provider metadata")
        ),
    )
    monkeypatch.setattr(oidc, "_exchange_code", lambda *args, **kwargs: "signed-token")
    monkeypatch.setattr(
        oidc,
        "_verify_id_token",
        lambda *args, **kwargs: {
            "sub": "employee-42",
            "preferred_username": "employee@example.com",
            "nonce": nonce,
        },
    )

    principal, return_to = oidc.complete_oidc(
        "code", state, CALLBACK_URL, browser_binding=binding
    )
    assert principal.username == "employee@example.com"
    assert return_to == "/"
    assert discovery_calls == [ISSUER]


def test_oidc_endpoint_policy_rejects_private_and_unapproved_origins():
    valid = _metadata()

    private = dict(valid, jwks_uri="https://127.0.0.1/jwks")
    with pytest.raises(ValueError, match="approved HTTPS"):
        oidc._validate_provider_metadata(private, ISSUER)

    cleartext = dict(valid, token_endpoint="http://idp.example.com/token")
    with pytest.raises(ValueError, match="approved HTTPS"):
        oidc._validate_provider_metadata(cleartext, ISSUER)

    cross_origin = dict(valid, authorization_endpoint="https://accounts.example.net/authorize")
    with pytest.raises(ValueError, match="approved HTTPS"):
        oidc._validate_provider_metadata(cross_origin, ISSUER)


def test_oidc_discovery_cache_is_ttl_bounded_and_does_not_follow_redirects(monkeypatch):
    oidc._clear_caches()
    calls = []

    class Response:
        def __init__(self, issuer):
            self._issuer = issuer

        def raise_for_status(self):
            return None

        def json(self):
            return _metadata(self._issuer)

    def fake_get(url, **kwargs):
        issuer = url.removesuffix("/.well-known/openid-configuration")
        calls.append((url, kwargs))
        return Response(issuer)

    monkeypatch.setattr(oidc.requests, "get", fake_get)
    for index in range(oidc.DISCOVERY_CACHE_MAX_ENTRIES + 5):
        issuer = f"https://idp-{index}.example.com"
        oidc._discovery(issuer)

    assert len(oidc._DISCOVERY_CACHE) == oidc.DISCOVERY_CACHE_MAX_ENTRIES
    assert all(kwargs["allow_redirects"] is False for _, kwargs in calls)


def test_oidc_verifies_id_token_with_bounded_jwks_fetch(monkeypatch):
    oidc._clear_caches()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()

    def encode_integer(value):
        size = (value.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "n": encode_integer(public_numbers.n),
                "e": encode_integer(public_numbers.e),
                "kid": "key-1",
                "alg": "RS256",
                "use": "sig",
            }
        ]
    }
    token = jwt.encode(
        {"sub": "employee-42", "iss": ISSUER, "aud": "client-id"},
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )

    class Response:
        status_code = 200
        content = json.dumps(jwks).encode()

        def raise_for_status(self):
            return None

        def json(self):
            return jwks

    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr(oidc.requests, "get", fake_get)
    metadata = oidc._validate_provider_metadata(_metadata(), ISSUER)
    claims = oidc._verify_id_token(token, metadata, "client-id")
    assert claims["sub"] == "employee-42"
    assert calls == [(metadata["jwks_uri"], {"timeout": 10, "allow_redirects": False})]


def test_oidc_start_sets_a_lax_http_only_browser_binding_cookie(monkeypatch):
    from app import main

    monkeypatch.setattr(
        main,
        "begin_oidc",
        lambda callback_url, return_to="/", *, browser_binding: "https://idp.example/authorize",
    )
    response = TestClient(main.app).get(
        "/api/auth/oidc/start", follow_redirects=False
    )
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert "aegis_oidc_binding=" in cookie
    assert "Max-Age=600" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
