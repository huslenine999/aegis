"""Validate the operator's permission matrix for the owned synthetic BAC lab."""

from __future__ import annotations

import hashlib
import json
import platform
import re
from copy import deepcopy
from datetime import datetime, timedelta
from importlib.metadata import version
from importlib.resources import as_file, files
from pathlib import Path

import requests

from .evidence import canonical_json, evidence_public_key, verify_manifest
from .resource_budgets import load_bounded_json, read_bounded_text
from .version import get_package_version


MAX_MATRIX_BYTES = 256 * 1024
MAX_PROTOCOL_BYTES = MAX_MATRIX_BYTES + 16 * 1024
MAX_CASES = 64
ACTORS = frozenset({"alice", "bob", "admin", "guest"})
OPERATIONS = frozenset({
    "read", "preview", "list", "export", "update", "rename", "delete", "admin-read", "admin-disable",
})
DOCUMENTS = frozenset({
    "alice-private-1", "bob-private-1", "alice-private-2", "bob-private-2",
    "alice-public", "bob-public",
})
SPLITS = frozenset({"development", "evaluation", "all"})
_IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z")
_CASE_FIELDS = {"id", "split", "operation", "actor", "resource", "expected_allowed"}


def validate_matrix(matrix: dict) -> dict:
    """Reject ambiguous input and return a fresh copy, never executable paths."""
    fields = {"schema_version", "corpus_id", "description", "cases"}
    if not isinstance(matrix, dict) or set(matrix) != fields:
        raise ValueError("BAC matrix must contain schema_version, corpus_id, description, and cases only.")
    if type(matrix["schema_version"]) is not int or matrix["schema_version"] != 1:
        raise ValueError("BAC matrix schema_version must be 1.")
    if not isinstance(matrix["corpus_id"], str) or not _IDENTIFIER.fullmatch(matrix["corpus_id"]):
        raise ValueError("BAC corpus_id must be a bounded identifier.")
    if not isinstance(matrix["description"], str) or len(matrix["description"]) > 2000:
        raise ValueError("BAC description must be text of at most 2000 characters.")
    cases = matrix["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError(f"BAC matrix must contain 1–{MAX_CASES} cases.")
    identifiers = []
    for case in cases:
        _validate_case(case)
        identifiers.append(case["id"])
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("BAC case identifiers must be unique.")
    return deepcopy(matrix)


def _validate_case(case: dict) -> None:
    if not isinstance(case, dict) or set(case) != _CASE_FIELDS:
        raise ValueError("BAC cases must contain only the documented permission fields.")
    if not isinstance(case["id"], str) or not _IDENTIFIER.fullmatch(case["id"]):
        raise ValueError("BAC case id must be a bounded, header-safe identifier.")
    for field, choices in (("actor", ACTORS), ("operation", OPERATIONS), ("split", SPLITS - {"all"})):
        if not isinstance(case[field], str) or case[field] not in choices:
            raise ValueError(f"Invalid BAC case {field}.")
    if type(case["expected_allowed"]) is not bool:
        raise ValueError("BAC expected_allowed must be a boolean, not text or a number.")
    operation = case["operation"]
    resource = case["resource"]
    resources = {"users"} if operation == "admin-read" else ACTORS - {"guest"} if operation == "admin-disable" else DOCUMENTS
    if not isinstance(resource, str) or resource not in resources:
        raise ValueError("BAC resource must identify a seeded lab object, never a URL or path.")
    if case["expected_allowed"] != intended_permission(case):
        raise ValueError("BAC permission labels must match the owned lab's documented permission rules.")


def intended_permission(case: dict) -> bool:
    if case["actor"] == "admin":
        return True
    if case["operation"].startswith("admin-"):
        return False
    if case["operation"] in {"read", "preview", "list", "export"} and case["resource"].endswith("-public"):
        return True
    return case["actor"] != "guest" and case["resource"].split("-", 1)[0] == case["actor"]


def load_matrix(path: str | Path | None = None) -> dict:
    if path is not None:
        return validate_matrix(load_bounded_json(Path(path).expanduser(), max_bytes=MAX_MATRIX_BYTES))
    with as_file(files("rules").joinpath("bac-matrix-v2.json")) as selected:
        return validate_matrix(load_bounded_json(selected, max_bytes=MAX_MATRIX_BYTES))


def select_cases(matrix: dict, split: str) -> list[dict]:
    if split not in SPLITS:
        raise ValueError("BAC split must be development, evaluation, or all.")
    cases = [case for case in matrix["cases"] if split == "all" or case["split"] == split]
    if not cases:
        raise ValueError("BAC matrix has no cases for the requested split.")
    return deepcopy(cases)


def research_versions() -> dict:
    """Share the existing runtime and five-module fingerprint contract."""
    return {
        "aegis": get_package_version(), "python": platform.python_version(),
        "requests": requests.__version__, "fastapi": version("fastapi"), "uvicorn": version("uvicorn"),
        "implementation_sha256": {
            name: hashlib.sha256(files("app").joinpath(name).read_bytes()).hexdigest()
            for name in ("bac.py", "bac_config.py", "bac_lab.py", "bac_reports.py", "bac_benchmark.py")
        },
    }


def study_definition(*, matrix: dict, split: str = "evaluation", repeats: int = 3) -> dict:
    """Freeze the same validated inputs and fingerprints used by the lab."""
    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError("repeats must be an integer from 1 to 20.")
    approved = validate_matrix(matrix)
    select_cases(approved, split)
    return {
        "schema_version": 1, "kind": "bac-study-protocol", "matrix": approved,
        "matrix_sha256": hashlib.sha256(canonical_json(approved)).hexdigest(),
        "split": split, "repeats": repeats, "versions": research_versions(),
    }


def _protocol_object(pairs: list[tuple[str, object]]) -> dict:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("Frozen BAC protocol contains duplicate JSON fields.")
    return dict(pairs)


def _reject_protocol_number(value: str) -> None:
    raise ValueError("Frozen BAC protocols require integer numbers, never nonfinite values.")


def _protocol_identity(protocol: dict) -> None:
    identifier = protocol["protocol_id"]
    if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier):
        raise ValueError("Invalid frozen BAC protocol identity.")
    timestamps = (protocol["created_at"], protocol["signed_at"])
    if any(not isinstance(value, str) or len(value) > 128 for value in timestamps):
        raise ValueError("Invalid frozen BAC protocol timestamp.")
    try:
        created, signed = (datetime.fromisoformat(value) for value in timestamps)
    except ValueError as exc:
        raise ValueError("Invalid frozen BAC protocol timestamp.") from exc
    if any(stamp.utcoffset() != timedelta(0) for stamp in (created, signed)) or signed < created:
        raise ValueError("Frozen BAC protocol timestamps must be ordered and UTC.")


def validate_study_protocol(path: str | Path, *, matrix: dict, split: str, repeats: int) -> dict:
    """Check local signer trust and exact preflight consistency, not execution attestation."""
    try:
        protocol = json.loads(
            read_bounded_text(Path(path).expanduser(), max_bytes=MAX_PROTOCOL_BYTES),
            object_pairs_hook=_protocol_object, parse_constant=_reject_protocol_number,
            parse_float=_reject_protocol_number,
        )
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid or oversized frozen BAC protocol JSON.") from exc
    current = study_definition(matrix=matrix, split=split, repeats=repeats)
    if not isinstance(protocol, dict) or set(protocol) != set(current) | {
        "protocol_id", "created_at", "signed_at", "signature",
    }:
        raise ValueError("Frozen BAC protocol must contain only the defined fields.")
    signature = protocol["signature"]
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "public_key", "value"}:
        raise ValueError("Invalid frozen BAC protocol signature fields.")
    trusted_key = evidence_public_key()["public_key"]
    if (not isinstance(signature["public_key"], str)
            or signature["public_key"].rstrip("=") != trusted_key.rstrip("=")
            or not verify_manifest(protocol, trusted_key, allow_embedded_key=False)):
        raise ValueError("Frozen BAC protocol signature does not match the configured signing identity.")
    _protocol_identity(protocol)
    for field, value in current.items():
        if canonical_json({"value": protocol[field]}) != canonical_json({"value": value}):
            raise ValueError(f"Frozen BAC protocol differs from the requested experiment: {field}.")
    return protocol
