import base64
import hashlib
import json
import os
import re
from copy import deepcopy
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def classify_source_attestation(manifest: dict) -> str:
    """Classify signed evidence without treating legacy manifests as attested."""
    if not isinstance(manifest, dict):
        return "invalid"
    source = manifest.get("source")
    if not isinstance(source, dict):
        return "legacy-source-unbound"
    attestation = source.get("attestation")
    manifest_schema = manifest.get("schema_version")
    if attestation is None or manifest_schema == 2:
        return "legacy-source-unbound"
    if not isinstance(manifest_schema, int) or manifest_schema < 3:
        return "invalid"
    if not isinstance(attestation, dict):
        return "invalid"
    if (
        attestation.get("schema_version") != 1
        or attestation.get("status") != "source-bound"
        or attestation.get("method") != "stable-copy"
        or not _HEX_DIGEST.fullmatch(str(attestation.get("descriptor_sha256", "")))
        or not _HEX_DIGEST.fullmatch(str(attestation.get("content_sha256", "")))
        or not _HEX_DIGEST.fullmatch(str(attestation.get("policy_sha256", "")))
    ):
        return "invalid"
    return "source-bound"


def verify_source_descriptor(manifest: dict, descriptor: dict) -> bool:
    """Verify the descriptor digests carried by a source-bound manifest."""
    if classify_source_attestation(manifest) != "source-bound":
        return False
    source = manifest["source"]
    attestation = source["attestation"]
    try:
        files = descriptor["files"]
        if not isinstance(files, list):
            return False
        descriptor_digest = hashlib.sha256(canonical_json(descriptor)).hexdigest()
        content_digest = hashlib.sha256(
            canonical_json(
                {
                    "schema_version": descriptor["schema_version"],
                    "files": [
                        {
                            "path": item["path"],
                            "sha256": item["sha256"],
                            "size": item["size"],
                        }
                        for item in files
                    ],
                }
            )
        ).hexdigest()
        return (
            descriptor_digest == attestation.get("descriptor_sha256")
            and content_digest == attestation.get("content_sha256")
            and descriptor.get("file_count") == attestation.get("file_count")
            and descriptor.get("total_bytes") == attestation.get("total_bytes")
        )
    except (KeyError, TypeError, ValueError):
        return False


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
