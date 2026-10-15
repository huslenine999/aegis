"""Admit signed individual BAC lab exports; signatures do not prove execution."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .artifact_storage import ArtifactLimitError, artifact_limits, validate_artifact_sizes
from .bac import evaluate_observation, probe_target
from .bac_config import ACTORS, DOCUMENTS, MAX_CASES, MAX_MATRIX_BYTES, SPLITS, select_cases, validate_matrix
from .evidence import canonical_json, verify_manifest


BAC_ARTIFACTS = {
    "scan-manifest.json": "application/json",
    "report.json": "application/json",
    "matrix.json": "application/json",
    "findings.json": "application/json",
    "evidence.json": "application/json",
    "server-events.json": "application/json",
    "report.md": "text/markdown",
    "report.html": "text/html",
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{43}=?\Z")
_CASE_FIELDS = {"id", "split", "actor", "operation", "resource", "expected_allowed"}
_BASELINE_FIELDS = {"baseline", "baseline_identity", "baseline_before", "baseline_after"}
_PROBE_FIELDS = {"probe", "before", "after"}
_TRACE_FIELDS = {"request_id", "timestamp", "actor", "method", "path", "request_body", "request_headers", "status_code", "body", "error"}
_EVENT_FIELDS = {"timestamp", "request_id", "case_id", "actor", "method", "path", "status_code"}
_IMPLEMENTATIONS = {"bac.py", "bac_config.py", "bac_lab.py", "bac_reports.py", "bac_benchmark.py"}
_STATUSES = {"allowed": 0, "blocked": 1, "error": 2}
_MAX_EVENTS = 4096


def _object(value: Any, required: set[str], label: str, optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - (optional or set()):
        raise ValueError(f"Invalid BAC {label} fields.")
    return value


def _text(value: Any, label: str, maximum: int, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or "\x00" in value:
        raise ValueError(f"Invalid BAC {label} text.")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"Invalid BAC {label} text encoding.") from exc
    return value


def _identifier(value: Any, label: str) -> str:
    if not _IDENTIFIER.fullmatch(_text(value, label, 128)):
        raise ValueError(f"Invalid BAC {label} identifier.")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("Invalid BAC SHA-256 digest.")
    return value


def _integer(value: Any, label: str, maximum: int, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid BAC {label} integer.")
    return value


def _timestamp(value: Any) -> datetime:
    text = _text(value, "timestamp", 40)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("Invalid BAC timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("BAC timestamps require a timezone.")
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("BAC JSON must not contain duplicate keys.")
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError("BAC JSON must contain finite numbers.")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("BAC JSON must contain finite numbers.")
    return parsed


def _json(content: bytes, name: str) -> Any:
    try:
        parsed = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object,
                            parse_constant=_reject_constant, parse_float=_finite_float)
        pending = [(parsed, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 32 or count > 250_000:
                raise ValueError("BAC JSON structure exceeds its limit.")
            if isinstance(value, dict):
                for key in value:
                    _text(key, "JSON key", 128)
                pending.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                if len(value) > _MAX_EVENTS:
                    raise ValueError("BAC JSON array exceeds its limit.")
                pending.extend((item, depth + 1) for item in value)
            elif isinstance(value, str):
                _text(value, "JSON value", 64 * 1024, minimum=0)
        return parsed
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"Invalid BAC JSON artifact: {name}.") from exc


def _same_json(actual: Any, expected: Any, label: str) -> None:
    if canonical_json({"value": actual}) != canonical_json({"value": expected}):
        raise ValueError(f"BAC {label} does not match the exported report.")


def _manifest(content: bytes, trusted_public_key: str) -> dict:
    manifest = _object(_json(content, "scan-manifest.json"), {
        "schema_version", "evidence_type", "aegis_version", "run_id", "status", "exit_code", "matrix_sha256",
        "started_at", "completed_at", "source_attestation", "artifacts", "signed_at", "signature",
    }, "manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 2:
        raise ValueError("BAC manifest schema_version must be 2.")
    if manifest["evidence_type"] != "bac-runtime-lab" or manifest["source_attestation"] != "not-claimed":
        raise ValueError("Only BAC runtime lab evidence without source attestation is supported.")
    signature = _object(manifest["signature"], {"algorithm", "key_id", "public_key", "value"}, "signature")
    if not isinstance(trusted_public_key, str) or not _PUBLIC_KEY.fullmatch(trusted_public_key):
        raise ValueError("A valid external BAC verification key is required.")
    if not isinstance(signature["public_key"], str) or signature["public_key"].rstrip("=") != trusted_public_key.rstrip("="):
        raise ValueError("BAC signature does not match the external verification key.")
    if not verify_manifest(manifest, trusted_public_key, allow_embedded_key=False):
        raise ValueError("BAC manifest signature verification failed.")
    _timestamp(manifest["signed_at"])
    _text(manifest["aegis_version"], "Aegis version", 128)
    return manifest


def _inventory(manifest: dict, artifacts: Mapping[str, bytes]) -> None:
    entries = manifest["artifacts"]
    expected = set(BAC_ARTIFACTS) - {"scan-manifest.json"}
    if not isinstance(entries, list) or len(entries) != len(expected):
        raise ValueError("BAC inventory must list every exported artifact exactly once.")
    names = []
    for entry in entries:
        item = _object(entry, {"name", "size", "sha256"}, "inventory entry")
        name = item["name"]
        if not isinstance(name, str) or name not in expected:
            raise ValueError("Invalid BAC inventory artifact name.")
        size = _integer(item["size"], "artifact size", artifact_limits()["per_artifact"])
        if size != len(artifacts[name]) or _digest(item["sha256"]) != hashlib.sha256(artifacts[name]).hexdigest():
            raise ValueError("BAC artifact inventory integrity check failed.")
        names.append(name)
    if set(names) != expected:
        raise ValueError("BAC inventory contains duplicate or missing artifacts.")


def _report_metadata(report: dict, manifest: dict, matrix: dict) -> None:
    if type(report["schema_version"]) is not int or report["schema_version"] != 1 or report["kind"] != "bac-research":
        raise ValueError("Only individual schema-1 BAC research reports are supported.")
    _identifier(report["run_id"], "run")
    if not isinstance(report["mode"], str) or report["mode"] not in {"fixed", "vulnerable"}:
        raise ValueError("Invalid BAC owned lab mode.")
    if not isinstance(report["split"], str) or report["split"] not in SPLITS:
        raise ValueError("Invalid BAC selected split.")
    if report["corpus_id"] != matrix["corpus_id"] or _digest(report["matrix_sha256"]) != hashlib.sha256(canonical_json(matrix)).hexdigest():
        raise ValueError("BAC report matrix or corpus does not match.")
    if _timestamp(report["completed_at"]) < _timestamp(report["started_at"]):
        raise ValueError("BAC completion precedes its start.")
    if not isinstance(report["status"], str) or report["status"] not in _STATUSES:
        raise ValueError("Invalid BAC report status.")
    _integer(report["exit_code"], "exit code", 2)
    for field in ("run_id", "status", "exit_code", "matrix_sha256", "started_at", "completed_at"):
        _same_json(manifest[field], report[field], f"manifest {field}")
    _text(report["output_dir"], "export directory", 4096)
    _text(report["manifest_path"], "export manifest path", 4096)


def _report_environment(report: dict, manifest: dict) -> None:
    versions = _object(report["versions"], {"aegis", "python", "requests", "fastapi", "uvicorn", "implementation_sha256"}, "versions")
    for field in ("aegis", "python", "requests", "fastapi", "uvicorn"):
        _text(versions[field], "runtime version", 128)
    if versions["aegis"] != manifest["aegis_version"]:
        raise ValueError("BAC report and manifest Aegis versions differ.")
    implementations = _object(versions["implementation_sha256"], _IMPLEMENTATIONS, "implementation versions")
    for digest in implementations.values():
        _digest(digest)
    lab = _object(report["lab"], {"instance_id", "seed_sha256"}, "owned lab")
    _identifier(lab["instance_id"], "lab instance")
    _digest(lab["seed_sha256"])
    limitations = report["limitations"]
    if not isinstance(limitations, list) or not 1 <= len(limitations) <= 20:
        raise ValueError("BAC report limitations must be a bounded text list.")
    for limitation in limitations:
        _text(limitation, "limitation", 4000)


def _snapshot(value: Any) -> None:
    snapshot = _object(value, {"documents", "users"}, "control snapshot")
    documents = _object(snapshot["documents"], set(), "snapshot documents", set(DOCUMENTS))
    for resource, record in documents.items():
        document = _object(record, {"id", "owner", "public", "title", "content"}, "snapshot document")
        if document["id"] != resource or document["owner"] != resource.split("-", 1)[0]:
            raise ValueError("BAC snapshot document identity does not match the seeded resource.")
        if type(document["public"]) is not bool or document["public"] != resource.endswith("-public"):
            raise ValueError("Invalid BAC snapshot document permission.")
        _text(document["title"], "document title", 200)
        _text(document["content"], "synthetic content", 4000)
    users = _object(snapshot["users"], set(ACTORS) - {"guest"}, "snapshot users")
    for actor, record in users.items():
        user = _object(record, {"id", "role", "active", "private_marker"}, "snapshot user")
        if user["id"] != actor or user["role"] != ("admin" if actor == "admin" else "user") or type(user["active"]) is not bool:
            raise ValueError("Invalid BAC snapshot user identity or activity.")
        _text(user["private_marker"], "synthetic user marker", 4000)


def _http_status(value: Any, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    _integer(value, "HTTP status", 599, minimum=100)


def _headers(value: Any) -> None:
    headers = _object(value, set(), "HTTP headers", set(value) if isinstance(value, dict) else set())
    if len(headers) > 64:
        raise ValueError("BAC HTTP headers exceed their limit.")
    for name, content in headers.items():
        if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", name):
            raise ValueError("Invalid BAC HTTP header name.")
        _text(content, "HTTP header", 8192, minimum=0)
        if name.lower() in {"authorization", "cookie", "set-cookie", "x-aegis-lab-key"} and content != "[REDACTED]":
            raise ValueError("BAC credential headers must be redacted.")


def _trace(value: Any, case_id: str) -> dict:
    trace = _object(value, _TRACE_FIELDS, "HTTP trace", {"response_headers"})
    _identifier(trace["request_id"], "request")
    _timestamp(trace["timestamp"])
    if not isinstance(trace["actor"], str) or trace["actor"] not in ACTORS:
        raise ValueError("Invalid BAC trace actor.")
    _http_status(trace["status_code"], optional=True)
    if trace["body"] is not None and not isinstance(trace["body"], dict):
        raise ValueError("BAC HTTP response body must be an object or null.")
    if trace["request_body"] is not None and not isinstance(trace["request_body"], dict):
        raise ValueError("BAC HTTP request body must be an object or null.")
    if trace["error"] is not None:
        _text(trace["error"], "HTTP error", 4000)
    _headers(trace["request_headers"])
    if trace["request_headers"].get("X-Aegis-Case-ID") != case_id or trace["request_headers"].get("X-Aegis-Request-ID") != trace["request_id"]:
        raise ValueError("BAC trace request correlation does not match its case.")
    if "response_headers" in trace:
        _headers(trace["response_headers"])
    return trace


def _probe(trace: dict, case: dict, actor: str) -> str:
    if trace["actor"] != actor or (trace["method"], trace["path"]) != probe_target(case):
        raise ValueError("BAC probe actor or operation does not match its matrix case.")
    if case["operation"] in {"update", "rename"}:
        body = _object(trace["request_body"], {"title"}, "update request")
        marker = _text(body["title"], "update marker", 200)
        if not marker.strip():
            raise ValueError("BAC update marker must contain text.")
        return marker
    if trace["request_body"] is not None:
        raise ValueError("Unexpected BAC operation request body.")
    return ""


def _identity(trace: dict, actor: str) -> None:
    if trace["actor"] != actor or trace["method"] != "GET" or trace["path"] != "/me" or trace["request_body"] is not None:
        raise ValueError("BAC identity trace does not match its actor.")
    if trace["error"] or trace["status_code"] != 200 or not isinstance(trace["body"], dict) or trace["body"].get("actor") != actor:
        raise ValueError("BAC identity confirmation is incomplete.")


def _events(value: Any, case: dict) -> list[dict]:
    if not isinstance(value, list) or len(value) > _MAX_EVENTS:
        raise ValueError("BAC server events must be a bounded list.")
    request_ids = []
    for raw in value:
        event = _object(raw, _EVENT_FIELDS, "server event")
        _identifier(event["request_id"], "server request")
        _timestamp(event["timestamp"])
        _http_status(event["status_code"])
        if event["case_id"] != case["id"] or not isinstance(event["actor"], str) or event["actor"] not in ACTORS:
            raise ValueError("BAC server event does not match its case or actor.")
        if (event["method"], event["path"]) not in (probe_target(case), ("GET", "/me")):
            raise ValueError("BAC server event does not match an owned lab operation.")
        request_ids.append(event["request_id"])
    if len(set(request_ids)) != len(request_ids):
        raise ValueError("BAC server request identifiers must be unique.")
    return value


def _validate_evidence(result: dict) -> None:
    evidence = _object(result["evidence"], set(), "case evidence", _BASELINE_FIELDS | _PROBE_FIELDS | {"probe_identity", "server_events"})
    for group in (_BASELINE_FIELDS, _PROBE_FIELDS):
        if group & evidence.keys() and not group <= evidence.keys():
            raise ValueError("BAC evidence contains an incomplete trace and snapshot group.")
    if result["expected_allowed"] and _BASELINE_FIELDS & evidence.keys():
        raise ValueError("Allowed BAC controls must not claim a forbidden-case baseline.")
    for field in ("baseline_before", "baseline_after", "before", "after"):
        if field in evidence:
            _snapshot(evidence[field])
    traces = {field: _trace(evidence[field], result["id"]) for field in ("probe", "baseline", "baseline_identity", "probe_identity") if field in evidence}
    if "probe_identity" in traces:
        if result["actor"] == "guest":
            raise ValueError("BAC guest cases must not claim authenticated identity confirmation.")
        _identity(traces["probe_identity"], result["actor"])
    if "probe" in traces:
        _probe(traces["probe"], result, result["actor"])
        _same_json(result["http_status"], traces["probe"]["status_code"], "case HTTP status")
    if "baseline" in traces:
        before = evidence["baseline_before"]
        owner = "admin" if result["operation"].startswith("admin-") else before["documents"].get(result["resource"], {}).get("owner")
        if owner not in ACTORS - {"guest"}:
            raise ValueError("BAC baseline resource owner is missing.")
        _identity(traces["baseline_identity"], owner)
        _probe(traces["baseline"], result, owner)
    events = _events(evidence["server_events"], result) if "server_events" in evidence else []
    if result["status"] != "inconclusive":
        required = _PROBE_FIELDS | {"server_events"} | (_BASELINE_FIELDS if not result["expected_allowed"] else set()) | ({"probe_identity"} if result["actor"] != "guest" else set())
        if not required <= evidence.keys():
            raise ValueError("Completed BAC cases require probe, identity, baseline, and audit evidence.")
        _completed_observation(result, evidence, traces, events)


def _completed_observation(result: dict, evidence: dict, traces: dict, events: list[dict]) -> None:
    probe = traces["probe"]
    marker = _probe(probe, result, result["actor"])
    verdict = evaluate_observation(result, probe, evidence["before"], evidence["after"], marker=marker)
    if verdict["status"] != result["status"]:
        raise ValueError("BAC classification is inconsistent with its observed permission effect.")
    if "baseline" in traces:
        baseline = traces["baseline"]
        if _probe(baseline, result, baseline["actor"]) != marker:
            raise ValueError("BAC baseline and probe mutation markers differ.")
        verdict = evaluate_observation({**result, "actor": baseline["actor"], "expected_allowed": True}, baseline,
                                       evidence["baseline_before"], evidence["baseline_after"], marker=marker)
        if verdict["status"] != "no_violation":
            raise ValueError("BAC authorized baseline did not complete its operation.")
    for trace in traces.values():
        if not any(all(event[field] == trace[field] for field in ("request_id", "actor", "method", "path", "status_code")) for event in events):
            raise ValueError("BAC completed trace has no matching server audit event.")


def _result(value: Any, cases: dict, mode: str) -> dict:
    result = _object(value, _CASE_FIELDS | {"status", "reason", "http_status", "duration_seconds", "evidence"}, "case result", {"trial_run_id", "mode", "repeat"})
    identifier = _identifier(result["id"], "case")
    if identifier not in cases or type(result["expected_allowed"]) is not bool:
        raise ValueError("Unexpected BAC result or invalid permission label.")
    for field in _CASE_FIELDS:
        _same_json(result[field], cases[identifier][field], f"case {field}")
    if not isinstance(result["status"], str) or result["status"] not in {"violation", "no_violation", "inconclusive"}:
        raise ValueError("Invalid BAC case verdict.")
    if result["expected_allowed"] and result["status"] == "violation":
        raise ValueError("An allowed BAC control cannot be a permission violation.")
    _text(result["reason"], "case reason", 4000)
    duration = result["duration_seconds"]
    if type(duration) not in {int, float} or not 0 <= duration <= 3600:
        raise ValueError("Invalid BAC case duration.")
    _http_status(result["http_status"], optional=result["status"] == "inconclusive")
    if "mode" in result and result["mode"] != mode:
        raise ValueError("BAC case mode differs from its individual report.")
    if "trial_run_id" in result:
        _identifier(result["trial_run_id"], "trial run")
    if "repeat" in result:
        _integer(result["repeat"], "trial repeat", 20, minimum=1)
    _validate_evidence(result)
    return result


def _findings(results: list[dict]) -> list[dict]:
    return [{
        "fingerprint": hashlib.sha256(canonical_json({key: row[key] for key in ("actor", "operation", "resource")})).hexdigest(),
        "tool": "BAC", "rule_id": row["operation"], "severity": "HIGH",
        "title": "Confirmed broken access control in synthetic lab", "case_id": row["id"],
        "actor": row["actor"], "resource": row["resource"], "reason": row["reason"], "evidence_artifact": "evidence.json",
    } for row in results if row["status"] == "violation"]


def _report(payloads: dict, manifest: dict, matrix: dict) -> dict:
    report = _object(payloads["report.json"], {
        "schema_version", "kind", "run_id", "mode", "split", "corpus_id", "matrix_sha256", "started_at", "completed_at",
        "versions", "lab", "status", "exit_code", "results", "findings", "metrics", "limitations", "output_dir", "manifest_path",
    }, "individual report")
    _report_metadata(report, manifest, matrix)
    _report_environment(report, manifest)
    selected = {case["id"]: case for case in select_cases(matrix, report["split"])}
    raw_results = report["results"]
    if not isinstance(raw_results, list) or len(raw_results) != len(selected):
        raise ValueError("BAC results must cover the selected matrix cases exactly.")
    results = [_result(value, selected, report["mode"]) for value in raw_results]
    if {row["id"] for row in results} != selected.keys():
        raise ValueError("BAC results contain duplicate or missing cases.")
    findings = _findings(results)
    _same_json(report["findings"], findings, "findings")
    _same_json(payloads["findings.json"], findings, "findings artifact")
    _report_counts(report, results, findings)
    evidence = [{
        "id": row["id"], "run_id": row.get("trial_run_id", report["run_id"]), "mode": row.get("mode", report["mode"]),
        "repeat": row.get("repeat"), "actor": row["actor"], "operation": row["operation"], "resource": row["resource"],
        "evidence": row["evidence"],
    } for row in results]
    _same_json(payloads["evidence.json"], evidence, "evidence artifact")
    events = [{**event, **{key: item[key] for key in ("run_id", "mode", "repeat")}}
              for item in evidence for event in item["evidence"].get("server_events", [])]
    _same_json(payloads["server-events.json"], events, "server events artifact")
    return report


def _report_counts(report: dict, results: list[dict], findings: list[dict]) -> None:
    metrics = _object(report["metrics"], {"cases", "violations", "inconclusive"}, "case metrics")
    for count in metrics.values():
        _integer(count, "case count", MAX_CASES)
    inconclusive = sum(row["status"] == "inconclusive" for row in results)
    _same_json(metrics, {"cases": len(results), "violations": len(findings), "inconclusive": inconclusive}, "case metrics")
    status = "error" if inconclusive else "blocked" if findings else "allowed"
    if report["status"] != status or report["exit_code"] != _STATUSES[status]:
        raise ValueError("BAC report status or exit code disagrees with its case outcomes.")


def validate_bac_bundle(artifacts: Mapping[str, bytes], trusted_public_key: str) -> dict:
    """Validate immutable upload bytes against the external pinned signer and BAC semantics."""
    if not isinstance(artifacts, Mapping):
        raise ValueError("BAC artifacts must be a mapping of basenames to bytes.")
    names = list(artifacts)
    if len(names) != len(BAC_ARTIFACTS) or any(not isinstance(name, str) for name in names) or set(names) != set(BAC_ARTIFACTS):
        raise ValueError("BAC upload must contain exactly the eight documented artifact basenames.")
    if any(not isinstance(artifacts[name], bytes) for name in names):
        raise ValueError("BAC artifact content must be bytes.")
    total = validate_artifact_sizes((name, len(artifacts[name])) for name in names)
    if total > artifact_limits()["bundle"]:
        raise ArtifactLimitError("BAC upload exceeds the report bundle byte limit.")
    if len(artifacts["matrix.json"]) > MAX_MATRIX_BYTES:
        raise ArtifactLimitError("BAC matrix exceeds its byte limit.")
    manifest = _manifest(artifacts["scan-manifest.json"], trusted_public_key)
    _inventory(manifest, artifacts)
    payloads = {name: _json(artifacts[name], name) for name in names if name.endswith(".json") and name != "scan-manifest.json"}
    matrix = validate_matrix(payloads["matrix.json"])
    report = _report(payloads, manifest, matrix)
    return {"manifest": manifest, "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
            "report": report, "matrix": matrix}
