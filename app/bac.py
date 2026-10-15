"""Role-aware BAC experiments against an owned, temporary loopback lab only."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .bac_config import ACTORS, research_versions, select_cases, validate_matrix
from .bac_config import load_matrix as load_matrix
from .bac_lab import local_bac_lab
from .bac_reports import export_report, redact, validate_output_directory
from .evidence import canonical_json


MAX_RESPONSE_BYTES = 64 * 1024
RUN_TIMEOUT_SECONDS = 60


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _observed_effect(case: dict, body: dict, before: dict, after: dict, marker: str) -> bool:
    operation, resource = case["operation"], case["resource"]
    if operation == "admin-read":
        canary = _state_record(before, "users", "admin")["private_marker"]
        if not isinstance(canary, str) or not canary:
            raise ValueError("Missing administrative content marker.")
        return body.get("private_marker") == canary and isinstance(body.get("users"), list)
    if operation == "admin-disable":
        original = _state_record(before, "users", resource)["active"]
        current = _state_record(after, "users", resource)["active"]
        if type(original) is not bool or type(current) is not bool:
            raise ValueError("Malformed user activity state.")
        return original is True and current is False
    document = _state_record(before, "documents", resource)
    if operation in {"list", "export"}:
        canary = document["content"]
        if not isinstance(canary, str) or not canary:
            raise ValueError("Missing private document marker.")
        return canary in json.dumps(body)
    if operation in {"read", "preview"}:
        canary = document["content"]
        if not isinstance(canary, str) or not canary or document["id"] != resource:
            raise ValueError("Missing private document marker or identity.")
        return body.get("id") == resource and body.get("content") == canary
    if operation == "delete":
        if not isinstance(after, dict) or not isinstance(after.get("documents"), dict):
            raise ValueError("Malformed deletion state.")
        return resource not in after["documents"]
    current = _state_record(after, "documents", resource)["title"]
    if not isinstance(document["title"], str) or not isinstance(current, str):
        raise ValueError("Malformed document title state.")
    return bool(marker) and document["title"] != marker and current == marker


def _state_record(snapshot: dict, collection: str, resource: str) -> dict:
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get(collection), dict):
        raise ValueError("Malformed control snapshot.")
    record = snapshot[collection].get(resource)
    if not isinstance(record, dict):
        raise ValueError("Missing or malformed seeded resource.")
    return record


def evaluate_observation(case: dict, observation: dict, before: dict, after: dict, *, marker: str = "") -> dict:
    """Use intended permissions and observed effects; never use lab bug labels."""
    code, body = observation.get("status_code"), observation.get("body")
    if observation.get("error") or type(code) is not int or not isinstance(body, dict):
        return {"status": "inconclusive", "reason": "No complete JSON observation was obtained."}
    try:
        effect = _observed_effect(case, body, before, after, marker)
    except (KeyError, TypeError, ValueError):
        return {"status": "inconclusive", "reason": "Seeded resource or state confirmation is missing."}
    if effect and not case["expected_allowed"]:
        return {"status": "violation", "reason": "Forbidden private data or state change was observed."}
    if code in {301, 302, 303, 307, 308, 429} or code >= 500 or (code == 401 and case["actor"] != "guest"):
        return {"status": "inconclusive", "reason": "Authentication, redirect, availability, or rate-limit failure."}
    if case["expected_allowed"] and (not effect or not 200 <= code < 300):
        return {"status": "inconclusive", "reason": "An allowed control did not complete its expected operation."}
    if not case["expected_allowed"] and code not in {200, 201, 202, 204, 401, 403, 404}:
        return {"status": "inconclusive", "reason": "The probe returned an unsupported response."}
    return {"status": "no_violation", "reason": "No forbidden effect was observed for this permission scenario."}


class _LabClient:
    """Own isolated actor sessions, a lab capability, and bounded HTTP evidence."""

    def __init__(self, lab):
        parsed = urlsplit(lab.base_url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("BAC experiments require the owned numeric-loopback lab origin.")
        self.lab = lab
        self.deadline = time.monotonic() + RUN_TIMEOUT_SECONDS
        self.sessions = {actor: requests.Session() for actor in (*sorted(ACTORS), "researcher")}
        for session in self.sessions.values():
            session.trust_env = False
        self.secrets = (*lab.tokens.values(), lab.control_token)

    def close(self) -> None:
        for session in self.sessions.values():
            session.close()

    def request(self, actor: str, method: str, path: str, case_id: str, *, body: dict | None = None) -> dict:
        request_id = uuid.uuid4().hex
        headers = {"X-Aegis-Request-ID": request_id, "X-Aegis-Case-ID": case_id}
        if actor == "researcher":
            headers = {**headers, "X-Aegis-Lab-Key": self.lab.control_token}
        elif actor != "guest":
            headers = {**headers, "Authorization": f"Bearer {self.lab.tokens[actor]}"}
        trace = {
            "request_id": request_id, "timestamp": _timestamp(), "actor": actor,
            "method": method, "path": path, "request_body": body,
            "request_headers": redact(headers, self.secrets),
            "status_code": None, "body": None, "error": None,
        }
        session = self.sessions[actor]
        session.cookies.clear()
        try:
            if time.monotonic() >= self.deadline:
                raise TimeoutError("BAC run deadline exceeded.")
            with session.request(method, self.lab.base_url + path, headers=headers, json=body, timeout=2, allow_redirects=False, stream=True) as response:
                trace = {**trace, "status_code": response.status_code}
                chunks, size = [], 0
                for chunk in response.iter_content(chunk_size=1024):
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES or time.monotonic() >= self.deadline:
                        raise ValueError("BAC response budget exceeded.")
                    chunks.append(chunk)
                if "application/json" not in response.headers.get("Content-Type", "").lower():
                    raise ValueError("BAC response must be JSON.")
                parsed = json.loads(b"".join(chunks))
                if not isinstance(parsed, dict):
                    raise ValueError("BAC response must be an object.")
                trace = {**trace, "body": parsed, "response_headers": redact(dict(response.headers), self.secrets)}
        except (requests.RequestException, ValueError, TimeoutError, UnicodeDecodeError):
            trace = {**trace, "error": "Incomplete or invalid lab HTTP response."}
        finally:
            session.cookies.clear()
        return redact(trace, self.secrets)

    def control(self, method: str, action: str, case_id: str) -> dict:
        trace = self.request("researcher", method, f"/_research/{action}", case_id)
        if trace["error"] or trace["status_code"] != 200:
            raise ValueError("Researcher lab control could not be verified.")
        return trace["body"]


def probe_target(case: dict) -> tuple[str, str]:
    """Map one matrix case to the single owned lab route it exercises."""
    operation, resource = case["operation"], case["resource"]
    return {
        "admin-read": ("GET", "/admin/users"),
        "admin-disable": ("POST", f"/admin/users/{resource}/disable"),
        "list": ("GET", "/documents"),
        "read": ("GET", f"/documents/{resource}"),
        "preview": ("GET", f"/documents/{resource}/preview"),
        "export": ("GET", f"/documents/{resource}/export"),
        "update": ("PATCH", f"/documents/{resource}"),
        "rename": ("PUT", f"/documents/{resource}/title"),
        "delete": ("DELETE", f"/documents/{resource}"),
    }[operation]


def _probe(client: _LabClient, case: dict, actor: str, marker: str) -> dict:
    operation = case["operation"]
    method, path = probe_target(case)
    return client.request(actor, method, path, case["id"], body={"title": marker} if operation in {"update", "rename"} else None)


def _check_identity(client: _LabClient, actor: str, case_id: str) -> dict:
    trace = client.request(actor, "GET", "/me", case_id)
    if trace["error"] or trace["status_code"] != 200 or trace["body"].get("actor") != actor:
        raise ValueError("The testing account could not be authenticated as the intended actor.")
    return trace


def _run_case(client: _LabClient, case: dict) -> dict:
    started = time.monotonic()
    marker = f"aegis-bac-{uuid.uuid4().hex}"
    evidence: dict = {}
    observation: dict = {}
    try:
        client.control("POST", "reset", case["id"])
        before = client.control("GET", "snapshot", case["id"])
        if not case["expected_allowed"]:
            owner = "admin" if case["operation"].startswith("admin-") else before["documents"][case["resource"]]["owner"]
            identity = _check_identity(client, owner, case["id"])
            baseline = _probe(client, case, owner, marker)
            baseline_after = client.control("GET", "snapshot", case["id"])
            baseline_verdict = evaluate_observation({**case, "actor": owner, "expected_allowed": True}, baseline, before, baseline_after, marker=marker)
            evidence = {"baseline_identity": identity, "baseline": baseline, "baseline_before": before, "baseline_after": baseline_after}
            if baseline_verdict["status"] != "no_violation":
                raise ValueError("The authorized baseline did not complete the expected operation.")
            client.control("POST", "reset", case["id"])
            before = client.control("GET", "snapshot", case["id"])
        if case["actor"] != "guest":
            evidence = {**evidence, "probe_identity": _check_identity(client, case["actor"], case["id"])}
        observation = _probe(client, case, case["actor"], marker)
        after = client.control("GET", "snapshot", case["id"])
        evidence = {**evidence, "probe": observation, "before": before, "after": after}
        verdict = evaluate_observation(case, observation, before, after, marker=marker)
        events = client.control("GET", f"events?case_id={case['id']}", case["id"]).get("events")
        if not isinstance(events, list) or not any(event.get("request_id") == observation["request_id"] and event.get("actor") == case["actor"] and event.get("status_code") == observation["status_code"] for event in events if isinstance(event, dict)):
            raise ValueError("The probe has no matching server-side audit event.")
        evidence = {**evidence, "server_events": events}
    except (ValueError, KeyError, TypeError) as exc:
        verdict = {"status": "inconclusive", "reason": str(exc)}
    return redact({
        **case, **verdict, "http_status": observation.get("status_code"),
        "duration_seconds": round(time.monotonic() - started, 6), "evidence": evidence,
    }, client.secrets)


def _finding(result: dict) -> dict:
    fingerprint = hashlib.sha256(canonical_json({key: result[key] for key in ("actor", "operation", "resource")})).hexdigest()
    return {
        "fingerprint": fingerprint, "tool": "BAC", "rule_id": result["operation"],
        "severity": "HIGH", "title": "Confirmed broken access control in synthetic lab",
        "case_id": result["id"], "actor": result["actor"], "resource": result["resource"],
        "reason": result["reason"], "evidence_artifact": "evidence.json",
    }


def run_research(*, mode: str, matrix: dict, split: str = "all", output_dir: str | Path) -> dict:
    approved = validate_matrix(matrix)
    cases = select_cases(approved, split)
    validate_output_directory(output_dir)
    if mode not in {"fixed", "vulnerable"}:
        raise ValueError("BAC lab mode must be fixed or vulnerable.")
    started_at = _timestamp()
    with local_bac_lab(mode) as lab:
        client = _LabClient(lab)
        try:
            info = client.control("GET", "info", "lab-handshake")
            if info.get("lab") != "aegis-bac-v2" or info.get("instance_id") != lab.instance_id:
                raise ValueError("The owned BAC lab identity handshake failed.")
            results = [_run_case(client, case) for case in cases]
        finally:
            client.close()
    findings = [_finding(result) for result in results if result["status"] == "violation"]
    incomplete = any(result["status"] == "inconclusive" for result in results)
    status, code = ("error", 2) if incomplete else ("blocked", 1) if findings else ("allowed", 0)
    report = {
        "schema_version": 1, "kind": "bac-research", "run_id": uuid.uuid4().hex,
        "mode": mode, "split": split, "corpus_id": approved["corpus_id"],
        "matrix_sha256": hashlib.sha256(canonical_json(approved)).hexdigest(),
        "started_at": started_at, "completed_at": _timestamp(),
        "versions": research_versions(),
        "lab": {"instance_id": info["instance_id"], "seed_sha256": info.get("seed_sha256")},
        "status": status, "exit_code": code, "results": results, "findings": findings,
        "metrics": {"cases": len(results), "violations": len(findings), "inconclusive": sum(item["status"] == "inconclusive" for item in results)},
        "limitations": ["Owned synthetic loopback lab only.", "Mutation confirmation uses researcher-only instrumented snapshots.", "No claim of real-world detection accuracy or source attestation."],
    }
    return export_report(report, approved, output_dir)
