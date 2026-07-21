import base64
import hashlib
import json
import os
from copy import deepcopy
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _decode_key(value: str) -> bytes:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
    except Exception as exc:
        raise RuntimeError(
            "AEGIS_EVIDENCE_SIGNING_KEY must be URL-safe base64."
        ) from exc
    if len(decoded) != 32:
        raise RuntimeError(
            "AEGIS_EVIDENCE_SIGNING_KEY must encode exactly 32 bytes."
        )
    return decoded


def _private_key() -> Ed25519PrivateKey:
    configured = os.environ.get("AEGIS_EVIDENCE_SIGNING_KEY", "")
    if configured:
        seed = _decode_key(configured)
    elif os.environ.get("AEGIS_ENV", "development").lower() == "production":
        raise RuntimeError("AEGIS_EVIDENCE_SIGNING_KEY is required in production.")
    else:
        # Local/test signatures are deterministic and explicitly not suitable as
        # a production trust anchor.
        seed = hashlib.sha256(b"aegis-development-evidence-key").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def evidence_public_key() -> dict:
    public = _private_key().public_key().public_bytes_raw()
    encoded = base64.urlsafe_b64encode(public).decode().rstrip("=")
    return {
        "algorithm": "Ed25519",
        "key_id": hashlib.sha256(public).hexdigest()[:24],
        "public_key": encoded,
    }


def sign_manifest(payload: dict) -> dict:
    unsigned = deepcopy(payload)
    unsigned.pop("signature", None)
    unsigned.setdefault("signed_at", datetime.now(timezone.utc).isoformat())
    signature = _private_key().sign(canonical_json(unsigned))
    signed = deepcopy(unsigned)
    signed["signature"] = {
        **evidence_public_key(),
        "value": base64.urlsafe_b64encode(signature).decode().rstrip("="),
    }
    return signed


def verify_manifest(
    manifest: dict,
    trusted_public_key: str | None = None,
    *,
    allow_embedded_key: bool = False,
) -> bool:
    try:
        unsigned = deepcopy(manifest)
        signature = unsigned.pop("signature")
        if not trusted_public_key and not allow_embedded_key:
            return False
        public_text = trusted_public_key or signature["public_key"]
        public_bytes = _decode_key(public_text)
        signature_value = base64.urlsafe_b64decode(
            signature["value"] + "=" * (-len(signature["value"]) % 4)
        )
        expected_key_id = hashlib.sha256(public_bytes).hexdigest()[:24]
        if signature.get("algorithm") != "Ed25519":
            return False
        if signature.get("key_id") != expected_key_id:
            return False
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature_value, canonical_json(unsigned)
        )
        return True
    except (KeyError, TypeError, ValueError, RuntimeError):
        return False
    except Exception:
        return False
