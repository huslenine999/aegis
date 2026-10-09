"""Synthetic exporter bundles: no lab process, scanner, Redis, or database."""

import copy
import hashlib
import json
from types import MappingProxyType

import pytest

from app.bac_imports import BAC_ARTIFACTS, validate_bac_bundle
from app.bac_reports import export_report
from app.evidence import canonical_json, evidence_public_key, sign_manifest
from app.version import get_package_version


TIMESTAMP = "2026-10-08T01:00:00+00:00"
DIGEST = "a" * 64


def synthetic_report(*, outcome="violation", mode="vulnerable", split="development", cases=None):
    """Return a complete individual report and matrix for integration tests."""
    matrix = {
        "schema_version": 1, "corpus_id": "import-test-v1", "description": "Owned synthetic test corpus.",
        "cases": cases or [
            {"id": "cross-owner", "split": "development", "actor": "alice", "operation": "read",
             "resource": "bob-private-1", "expected_allowed": False},
            {"id": "allowed-owner", "split": "development", "actor": "bob", "operation": "read",
             "resource": "bob-private-1", "expected_allowed": True},
            {"id": "guest-preview", "split": "evaluation", "actor": "guest", "operation": "preview",
             "resource": "bob-private-1", "expected_allowed": False},
        ],
    }
    snapshot = {
        "documents": {"bob-private-1": {"id": "bob-private-1", "owner": "bob", "public": False,
                                        "title": "Bob private", "content": "synthetic-bob-canary"}},
        "users": {actor: {"id": actor, "role": "admin" if actor == "admin" else "user", "active": True,
                          "private_marker": f"synthetic-{actor}-marker"} for actor in ("alice", "bob", "admin")},
    }

    def trace(case, actor, suffix, path, body, status=200, method="GET", request_body=None):
        return {
            "request_id": f"{case['id']}-{suffix}", "timestamp": TIMESTAMP, "actor": actor,
            "method": method, "path": path, "request_body": request_body,
            "request_headers": {"Authorization": "[REDACTED]", "X-Aegis-Case-ID": case["id"],
                                "X-Aegis-Request-ID": f"{case['id']}-{suffix}"},
            "status_code": status, "body": body, "error": None, "response_headers": {"Content-Type": "application/json"},
        }

    results = []
    for case in matrix["cases"]:
        if split != "all" and case["split"] != split:
            continue
        verdict = "no_violation" if case["expected_allowed"] or case["actor"] == "guest" else outcome
        operation, resource = case["operation"], case["resource"]
        path = ("/admin/users" if operation == "admin-read" else f"/admin/users/{resource}/disable" if operation == "admin-disable"
                else "/documents/" + resource + ("/preview" if operation == "preview" else ""))
        method = {"read": "GET", "preview": "GET", "update": "PATCH", "delete": "DELETE", "admin-read": "GET", "admin-disable": "POST"}[operation]
        request_body = {"title": "synthetic-update-marker"} if operation == "update" else None

        def completed_effect():
            after = copy.deepcopy(snapshot)
            if operation == "admin-read":
                response = {"users": list(after["users"].values()), "private_marker": after["users"]["admin"]["private_marker"]}
            elif operation == "admin-disable":
                after["users"][resource]["active"] = False
                response = after["users"][resource]
            elif operation == "delete":
                after["documents"].pop(resource)
                response = {"deleted": resource}
            else:
                if operation == "update":
                    after["documents"][resource]["title"] = request_body["title"]
                response = after["documents"][resource]
            return after, response

        baseline_after, baseline_response = completed_effect()
        after, response = (baseline_after, baseline_response) if verdict == "violation" or case["expected_allowed"] else (snapshot, {"detail": "Denied"})
        probe = trace(case, case["actor"], "probe", path, response, 200 if verdict == "violation" or case["expected_allowed"] else 403, method, request_body)
        evidence = {"probe": probe, "before": copy.deepcopy(snapshot), "after": copy.deepcopy(after)}
        if not case["expected_allowed"]:
            owner = "admin" if operation.startswith("admin-") else snapshot["documents"][resource]["owner"]
            evidence = {**evidence,
                        "baseline_identity": trace(case, owner, "baseline-id", "/me", {"actor": owner, "role": "admin" if owner == "admin" else "user"}),
                        "baseline": trace(case, owner, "baseline", path, baseline_response, method=method, request_body=request_body),
                        "baseline_before": copy.deepcopy(snapshot), "baseline_after": copy.deepcopy(baseline_after)}
        if case["actor"] != "guest":
            evidence = {**evidence, "probe_identity": trace(case, case["actor"], "identity", "/me", {"actor": case["actor"], "role": "user"})}
        evidence = {**evidence, "server_events": [
            {"timestamp": TIMESTAMP, "request_id": observation["request_id"], "case_id": case["id"],
             "actor": observation["actor"], "method": observation["method"], "path": observation["path"],
             "status_code": observation["status_code"]}
            for name, observation in evidence.items() if name in {"probe", "baseline", "probe_identity", "baseline_identity"}
        ]}
        results.append({**case, "status": verdict, "reason": "Synthetic observed outcome.",
                        "http_status": probe["status_code"], "duration_seconds": 0.1,
                        "evidence": {} if verdict == "inconclusive" else evidence})
    findings = [
        {"fingerprint": hashlib.sha256(canonical_json({key: row[key] for key in ("actor", "operation", "resource")})).hexdigest(),
         "tool": "BAC", "rule_id": row["operation"], "severity": "HIGH",
         "title": "Confirmed broken access control in synthetic lab", "case_id": row["id"],
         "actor": row["actor"], "resource": row["resource"], "reason": row["reason"], "evidence_artifact": "evidence.json"}
        for row in results if row["status"] == "violation"
    ]
    incomplete = sum(row["status"] == "inconclusive" for row in results)
    status = "error" if incomplete else "blocked" if findings else "allowed"
    report = {
        "schema_version": 1, "kind": "bac-research", "run_id": "synthetic-run-1", "mode": mode,
        "split": split, "corpus_id": matrix["corpus_id"],
        "matrix_sha256": hashlib.sha256(canonical_json(matrix)).hexdigest(),
        "started_at": TIMESTAMP, "completed_at": "2026-10-08T01:01:00+00:00",
        "versions": {"aegis": get_package_version(), "python": "3.13.5", "requests": "2.34.2", "fastapi": "0.138.1",
                     "uvicorn": "0.49.0", "implementation_sha256": {name: DIGEST for name in
                         ("bac.py", "bac_config.py", "bac_lab.py", "bac_reports.py", "bac_benchmark.py")}},
        "lab": {"instance_id": "synthetic-lab-1", "seed_sha256": DIGEST},
        "status": status, "exit_code": {"allowed": 0, "blocked": 1, "error": 2}[status],
        "results": results, "findings": findings,
        "metrics": {"cases": len(results), "violations": len(findings), "inconclusive": incomplete},
        "limitations": ["Owned synthetic loopback lab only.", "Signatures do not prove execution correctness."],
    }
    return report, matrix


def exported_bundle(directory, **options):
    """Export the fixture; return exact upload bytes and an independently selected key."""
    report, matrix = synthetic_report(**options)
    export_report(report, matrix, directory)
    return {path.name: path.read_bytes() for path in directory.iterdir()}, evidence_public_key()["public_key"]


def resigned_bundle(artifacts, *, updates=None, manifest_updates=None):
    changed = {**artifacts, **{name: canonical_json(value) for name, value in (updates or {}).items()}}
    manifest = {**json.loads(artifacts["scan-manifest.json"]), **(manifest_updates or {})}
    manifest["artifacts"] = [
        {"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        for name, content in changed.items() if name != "scan-manifest.json"
    ]
    return {**changed, "scan-manifest.json": canonical_json(sign_manifest(manifest))}


def resigned_report_bundle(artifacts, report):
    evidence = [{"id": row["id"], "run_id": row.get("trial_run_id", report["run_id"]),
                 "mode": row.get("mode", report["mode"]), "repeat": row.get("repeat"),
                 "actor": row["actor"], "operation": row["operation"], "resource": row["resource"], "evidence": row["evidence"]}
                for row in report["results"]]
    events = [{**event, **{key: item[key] for key in ("run_id", "mode", "repeat")}}
              for item in evidence for event in item["evidence"].get("server_events", []) if isinstance(event, dict)]
    return resigned_bundle(artifacts, updates={"report.json": report, "findings.json": report["findings"],
                                              "evidence.json": evidence, "server-events.json": events})


@pytest.fixture
def bundle(tmp_path):
    return exported_bundle(tmp_path / "export")


@pytest.mark.parametrize("outcome", ["no_violation", "violation", "inconclusive"])
def test_accepts_current_individual_exports_and_returns_canonical_identity(tmp_path, outcome):
    artifacts, key = exported_bundle(tmp_path / "export", outcome=outcome)
    original = copy.deepcopy(artifacts)
    result = validate_bac_bundle(MappingProxyType(artifacts), key)
    assert set(result) == {"manifest", "manifest_sha256", "report", "matrix"}
    assert result["report"] == json.loads(artifacts["report.json"])
    assert result["matrix"] == json.loads(artifacts["matrix.json"])
    assert result["manifest_sha256"] == hashlib.sha256(canonical_json(result["manifest"])).hexdigest()
    assert artifacts == original


def test_artifact_allowlist_is_exact():
    assert BAC_ARTIFACTS == {
        "scan-manifest.json": "application/json", "report.json": "application/json", "matrix.json": "application/json",
        "findings.json": "application/json", "evidence.json": "application/json", "server-events.json": "application/json",
        "report.md": "text/markdown", "report.html": "text/html",
    }


@pytest.mark.parametrize("key", ["", None, True, "invalid-key", "A" * 43])
def test_requires_external_pinned_key(bundle, key):
    artifacts, _ = bundle
    with pytest.raises(ValueError, match="key|signature"):
        validate_bac_bundle(artifacts, key)


@pytest.mark.parametrize("name", ["report.json", "scan-manifest.json", "evidence.json", "report.md", "report.html"])
def test_rejects_missing_and_tampered_artifacts(bundle, name):
    artifacts, key = bundle
    with pytest.raises(ValueError):
        validate_bac_bundle({key: value for key, value in artifacts.items() if key != name}, key)
    tampered = artifacts[name].replace(b"synthetic-run-1", b"forged-run-1") if name == "scan-manifest.json" else artifacts[name] + b" "
    with pytest.raises(ValueError):
        validate_bac_bundle({**artifacts, name: tampered}, key)


def test_manifest_formatting_does_not_change_canonical_identity(bundle):
    artifacts, key = bundle
    original = validate_bac_bundle(artifacts, key)
    pretty = {**artifacts, "scan-manifest.json": json.dumps(original["manifest"], indent=2).encode()}
    assert validate_bac_bundle(pretty, key)["manifest_sha256"] == original["manifest_sha256"]


@pytest.mark.parametrize("name", ["../report.json", "/report.json", "nested/report.json", "report.json\\extra", "other.json", "report.json\x00"])
def test_rejects_extra_or_unsafe_upload_names(bundle, name):
    artifacts, key = bundle
    with pytest.raises(ValueError):
        validate_bac_bundle({**artifacts, name: b"{}"}, key)


@pytest.mark.parametrize("name,value", [("report.json", {}), ("report.json", "{}"), ("report.md", bytearray(b"x"))])
def test_requires_byte_content(bundle, name, value):
    artifacts, key = bundle
    with pytest.raises(ValueError):
        validate_bac_bundle({**artifacts, name: value}, key)


@pytest.mark.parametrize("field,value", [
    ("schema_version", 1), ("schema_version", True), ("evidence_type", "source-scan"),
    ("source_attestation", "source-bound"), ("source", {"attestation": {"status": "source-bound"}}),
    ("run_id", "different"), ("status", "allowed"), ("exit_code", 0), ("exit_code", True),
    ("matrix_sha256", "0" * 64), ("started_at", "2026-10-08T00:00:00+00:00"),
    ("completed_at", "2026-10-08T02:00:00+00:00"), ("signed_at", "invalid"),
])
def test_rejects_re_signed_manifest_semantic_mismatches(bundle, field, value):
    artifacts, key = bundle
    changed = resigned_bundle(artifacts, manifest_updates={field: value})
    with pytest.raises(ValueError):
        validate_bac_bundle(changed, key)


@pytest.mark.parametrize("change", ["duplicate", "missing", "extra", "unsafe", "size-bool", "size-text", "size-negative", "wrong-size", "wrong-hash", "malformed"])
def test_rejects_invalid_signed_inventory(bundle, change):
    artifacts, key = bundle
    manifest = json.loads(artifacts["scan-manifest.json"])
    entries = manifest["artifacts"]
    if change == "duplicate":
        manifest["artifacts"] = [*entries, entries[0]]
    elif change == "missing":
        manifest["artifacts"] = entries[:-1]
    elif change == "extra":
        manifest["artifacts"] = [*entries, {"name": "other.json", "size": 0, "sha256": DIGEST}]
    elif change == "malformed":
        manifest["artifacts"] = [None, *entries[1:]]
    else:
        replacements = {"unsafe": {"name": "../report.json"}, "size-bool": {"size": True},
                        "size-text": {"size": str(entries[0]["size"])}, "size-negative": {"size": -1},
                        "wrong-size": {"size": 0}, "wrong-hash": {"sha256": DIGEST}}
        manifest["artifacts"] = [{**entries[0], **replacements[change]}, *entries[1:]]
    with pytest.raises(ValueError):
        validate_bac_bundle({**artifacts, "scan-manifest.json": canonical_json(sign_manifest(manifest))}, key)


@pytest.mark.parametrize("name", ["scan-manifest.json", "report.json", "matrix.json", "findings.json", "evidence.json", "server-events.json"])
@pytest.mark.parametrize("content", [b'{"kind":"bac-research","kind":"bac-research"}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'\xff', b'{'])
def test_strict_json_rejects_ambiguous_or_invalid_values(bundle, name, content):
    artifacts, key = bundle
    changed = {**artifacts, name: content}
    if name != "scan-manifest.json":
        changed = resigned_bundle(changed)
    with pytest.raises(ValueError):
        validate_bac_bundle(changed, key)


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("kind", "bac-benchmark"), ("kind", "source-scan"),
    ("run_id", "../other"), ("run_id", []), ("mode", "remote"), ("split", "training"),
    ("corpus_id", "another-corpus"), ("matrix_sha256", DIGEST), ("started_at", "bad"),
    ("completed_at", "2020-01-01T00:00:00+00:00"), ("started_at", "2026-10-08T01:00:00"),
    ("status", "allowed"), ("exit_code", 0), ("exit_code", True),
    ("results", {}), ("findings", {}), ("metrics", {"cases": True, "violations": 1, "inconclusive": 0}),
    ("metrics", {"cases": 2, "violations": 0, "inconclusive": 0}), ("lab", {"instance_id": "lab"}),
    ("versions", []), ("limitations", "none"), ("output_dir", []), ("foreign_scanner", {"report": []}),
])
def test_rejects_malformed_or_foreign_reports(bundle, field, value):
    artifacts, key = bundle
    report = {**json.loads(artifacts["report.json"]), field: value}
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_bundle(artifacts, updates={"report.json": report}), key)


@pytest.mark.parametrize("change", ["duplicate", "missing", "unexpected", "wrong-split", "forged-permission", "invalid-verdict", "allowed-violation", "reason-object", "reason-limit", "bad-duration", "bool-duration", "bad-http", "foreign", "bad-evidence"])
def test_rejects_invalid_case_results(bundle, change):
    artifacts, key = bundle
    report = json.loads(artifacts["report.json"])
    rows = report["results"]
    replacements = {
        "unexpected": {"id": "other"}, "wrong-split": {"split": "evaluation"},
        "forged-permission": {"expected_allowed": True}, "invalid-verdict": {"status": "secure"},
        "reason-object": {"reason": {}}, "reason-limit": {"reason": "x" * 4001},
        "bad-duration": {"duration_seconds": -1}, "bool-duration": {"duration_seconds": True},
        "bad-http": {"http_status": True}, "foreign": {"tool": "Semgrep"}, "bad-evidence": {"evidence": []},
    }
    if change == "duplicate":
        report["results"] = [rows[0], rows[0]]
    elif change == "missing":
        report["results"] = rows[:-1]
    elif change == "allowed-violation":
        report["results"] = [rows[0], {**rows[1], "status": "violation"}]
    else:
        report["results"] = [{**rows[0], **replacements[change]}, rows[1]]
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_bundle(artifacts, updates={"report.json": report}), key)


@pytest.mark.parametrize("artifact", ["findings.json", "evidence.json", "server-events.json"])
def test_rejects_re_signed_cross_artifact_disagreement(bundle, artifact):
    artifacts, key = bundle
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_bundle(artifacts, updates={artifact: []}), key)


def test_forged_scanner_finding_cannot_be_admitted(bundle):
    artifacts, key = bundle
    report = json.loads(artifacts["report.json"])
    report["findings"][0] = {**report["findings"][0], "tool": "Semgrep", "file": "private.py"}
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_bundle(artifacts, updates={"report.json": report, "findings.json": report["findings"]}), key)


def test_explicit_trial_attribution_matches_exporter(tmp_path):
    report, matrix = synthetic_report()
    report["results"] = [{**row, "trial_run_id": "trial-run-1", "mode": report["mode"], "repeat": 1} for row in report["results"]]
    destination = tmp_path / "trial"
    export_report(report, matrix, destination)
    artifacts = {path.name: path.read_bytes() for path in destination.iterdir()}
    result = validate_bac_bundle(artifacts, evidence_public_key()["public_key"])
    assert result["report"]["results"][0]["trial_run_id"] == "trial-run-1"
    assert json.loads(artifacts["evidence.json"])[0]["run_id"] == "trial-run-1"


def test_mode_is_metadata_not_ground_truth(tmp_path):
    artifacts, key = exported_bundle(tmp_path / "fixed", mode="fixed", outcome="violation")
    assert validate_bac_bundle(artifacts, key)["report"]["status"] == "blocked"


@pytest.mark.parametrize("operation,resource", [("read", "bob-private-1"), ("preview", "bob-private-1"),
    ("update", "bob-private-1"), ("delete", "bob-private-1"), ("admin-read", "users"), ("admin-disable", "bob")])
@pytest.mark.parametrize("outcome", ["violation", "no_violation"])
def test_current_read_mutation_and_admin_evidence_is_accepted(tmp_path, operation, resource, outcome):
    case = {"id": "operation-case", "split": "development", "actor": "alice", "operation": operation,
            "resource": resource, "expected_allowed": False}
    artifacts, key = exported_bundle(tmp_path / "operation", outcome=outcome, cases=[case])
    assert validate_bac_bundle(artifacts, key)["report"]["results"][0]["status"] == outcome


@pytest.mark.parametrize("split,count", [("development", 2), ("evaluation", 1), ("all", 3)])
def test_covers_only_the_requested_matrix_split(tmp_path, split, count):
    artifacts, key = exported_bundle(tmp_path / split, split=split)
    assert len(validate_bac_bundle(artifacts, key)["report"]["results"]) == count


@pytest.mark.parametrize("path,value", [
    (("probe", "body"), {}), (("probe", "actor"), "bob"), (("probe", "method"), "POST"),
    (("probe", "path"), "http://example.test/documents/bob-private-1"), (("probe", "timestamp"), "invalid"),
    (("probe", "request_id"), "unsafe\nheader"), (("probe", "request_body"), []), (("probe", "error"), {}),
    (("probe", "body"), []), (("probe", "status_code"), True), (("probe", "extra"), "foreign"),
    (("probe", "request_headers", "Authorization"), "Bearer unredacted-secret"),
    (("probe", "request_headers", "X-Aegis-Case-ID"), "other-case"),
    (("probe", "request_headers", "X-Aegis-Request-ID"), "other-request"),
    (("probe", "response_headers", "Set-Cookie"), "session=unredacted-secret"),
    (("baseline_identity", "body", "actor"), "alice"), (("baseline_identity", "status_code"), 401),
    (("baseline", "body"), {}), (("baseline", "actor"), "alice"),
    (("before", "documents", "bob-private-1", "owner"), "alice"),
    (("before", "documents", "bob-private-1", "public"), "false"),
    (("before", "users", "bob", "active"), "true"), (("before", "users", "bob", "role"), "admin"),
    (("server_events", 0, "case_id"), "foreign-case"), (("server_events", 0, "actor"), "foreign-actor"),
    (("server_events", 0, "status_code"), True), (("server_events", 0, "path"), "/foreign-api"),
    (("server_events", 0, "method"), []), (("server_events", 0, "request_id"), "different-request"),
])
def test_rejects_coherently_exported_but_invalid_evidence(bundle, path, value):
    artifacts, key = bundle
    report = json.loads(artifacts["report.json"])
    target = report["results"][0]["evidence"]
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_report_bundle(artifacts, report), key)


@pytest.mark.parametrize("change", ["missing-probe", "partial-probe", "partial-baseline", "missing-audit", "duplicate-audit", "bad-audit", "allowed-baseline", "guest-identity"])
def test_rejects_incomplete_or_impossible_evidence_groups(tmp_path, change):
    artifacts, key = exported_bundle(tmp_path / "export", split="all")
    report = json.loads(artifacts["report.json"])
    evidence = report["results"][0]["evidence"]
    if change == "missing-probe":
        for field in ("probe", "before", "after"):
            evidence.pop(field)
    elif change == "partial-probe":
        evidence.pop("after")
    elif change == "partial-baseline":
        evidence.pop("baseline_after")
    elif change == "missing-audit":
        evidence.pop("server_events")
    elif change == "duplicate-audit":
        evidence["server_events"].append(evidence["server_events"][0])
    elif change == "bad-audit":
        evidence["server_events"] = [None]
    elif change == "allowed-baseline":
        report["results"][1]["evidence"] = {**report["results"][1]["evidence"],
            **{field: evidence[field] for field in ("baseline", "baseline_identity", "baseline_before", "baseline_after")}}
    else:
        report["results"][2]["evidence"]["probe_identity"] = evidence["probe_identity"]
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_report_bundle(artifacts, report), key)


def test_inconclusive_run_may_preserve_partial_successful_evidence(tmp_path):
    artifacts, key = exported_bundle(tmp_path / "error", outcome="inconclusive")
    report = json.loads(artifacts["report.json"])
    complete, _ = synthetic_report()
    report["results"][0]["evidence"] = {name: value for name, value in complete["results"][0]["evidence"].items() if name != "server_events"}
    report["results"][0]["http_status"] = 200
    assert validate_bac_bundle(resigned_report_bundle(artifacts, report), key)["report"]["status"] == "error"


def test_denial_that_leaks_content_still_confirms_a_violation(bundle):
    artifacts, key = bundle
    report = json.loads(artifacts["report.json"])
    row = report["results"][0]
    row["http_status"] = 403
    row["evidence"]["probe"]["status_code"] = 403
    row["evidence"]["server_events"][0]["status_code"] = 403
    assert validate_bac_bundle(resigned_report_bundle(artifacts, report), key)["report"]["status"] == "blocked"


def test_failed_allowed_control_is_not_a_completed_no_violation(bundle):
    artifacts, key = bundle
    report = json.loads(artifacts["report.json"])
    row = report["results"][1]
    row["http_status"] = 403
    row["evidence"]["probe"]["status_code"] = 403
    row["evidence"]["server_events"][0]["status_code"] = 403
    with pytest.raises(ValueError, match="classification"):
        validate_bac_bundle(resigned_report_bundle(artifacts, report), key)


@pytest.mark.parametrize("value", [{}, [], None, "bundle"])
def test_rejects_non_bundle_input(value):
    with pytest.raises(ValueError):
        validate_bac_bundle(value, evidence_public_key()["public_key"])


def test_result_downgrade_cannot_hide_confirmed_effect(tmp_path):
    artifacts, key = exported_bundle(tmp_path / "no-violation", outcome="no_violation")
    report = json.loads(artifacts["report.json"])
    row = report["results"][0]
    row["evidence"]["probe"]["body"] = row["evidence"]["before"]["documents"][row["resource"]]
    with pytest.raises(ValueError, match="classification"):
        validate_bac_bundle(resigned_report_bundle(artifacts, report), key)


@pytest.mark.parametrize("limit", ["AEGIS_MAX_ARTIFACT_BYTES", "AEGIS_MAX_TOTAL_ARTIFACT_BYTES", "AEGIS_MAX_REPORT_BUNDLE_BYTES"])
def test_applies_existing_artifact_limits_before_parsing(bundle, monkeypatch, limit):
    artifacts, key = bundle
    monkeypatch.setenv(limit, "1")
    with pytest.raises(ValueError, match="limit"):
        validate_bac_bundle(artifacts, key)


def test_manifest_itself_is_included_in_per_artifact_budget(bundle, monkeypatch):
    artifacts, key = bundle
    largest = max(len(value) for name, value in artifacts.items() if name != "scan-manifest.json")
    manifest = json.loads(artifacts["scan-manifest.json"])
    manifest["aegis_version"] = "x" * (largest + 1)
    changed = {**artifacts, "scan-manifest.json": canonical_json(sign_manifest(manifest))}
    monkeypatch.setenv("AEGIS_MAX_ARTIFACT_BYTES", str(largest))
    with pytest.raises(ValueError, match="limit"):
        validate_bac_bundle(changed, key)


@pytest.mark.parametrize("field,value", [("mode", "fixed"), ("trial_run_id", "../foreign"), ("repeat", True), ("repeat", 0), ("repeat", 21)])
def test_trial_attribution_requires_the_current_individual_format(bundle, field, value):
    artifacts, key = bundle
    report = json.loads(artifacts["report.json"])
    report["results"][0][field] = value
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_report_bundle(artifacts, report), key)


@pytest.mark.parametrize("content", [b'{"reason":"\\ud800"}', b'{"reason":"\\u0000"}', b'{"array":[' + b'0,' * 4096 + b'0]}',
                                     b'{"nested":' * 34 + b'0' + b'}' * 34])
def test_json_structure_and_encoding_have_bounded_limits(bundle, content):
    artifacts, key = bundle
    with pytest.raises(ValueError):
        validate_bac_bundle(resigned_bundle({**artifacts, "report.json": content}), key)


def test_matrix_retains_its_existing_smaller_budget(bundle):
    artifacts, key = bundle
    changed = {**artifacts, "matrix.json": b" " * (256 * 1024 + 1)}
    with pytest.raises(ValueError, match="matrix.*limit"):
        validate_bac_bundle(resigned_bundle(changed), key)


def test_manifest_signature_failure_does_not_expose_sensitive_data(bundle):
    artifacts, key = bundle
    manifest = json.loads(artifacts["scan-manifest.json"])
    manifest["signature"]["value"] = "private-sensitive-value"
    with pytest.raises(ValueError) as error:
        validate_bac_bundle({**artifacts, "scan-manifest.json": canonical_json(manifest)}, key)
    assert "private-sensitive-value" not in str(error.value)
