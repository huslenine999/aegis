import copy
import json
from pathlib import Path

import pytest

from app.bac import evaluate_observation, load_matrix, run_research
from app.bac_config import validate_matrix
from app.bac_reports import export_report, redact
from app.evidence import evidence_public_key, verify_manifest


def matrix_case(**changes):
    return {
        "id": "alice-cross-owner-read",
        "split": "development",
        "operation": "read",
        "actor": "alice",
        "resource": "bob-private-1",
        "expected_allowed": False,
        **changes,
    }


def matrix_with(*cases):
    return {
        "schema_version": 1,
        "corpus_id": "test-bac-v1",
        "description": "Synthetic test matrix.",
        "cases": list(cases or (matrix_case(),)),
    }


def state():
    return {
        "documents": {
            "bob-private-1": {
                "id": "bob-private-1", "owner": "bob", "public": False,
                "title": "Bob private", "content": "synthetic-bob-canary",
            }
        },
        "users": {
            "alice": {"id": "alice", "role": "user", "active": True},
            "bob": {"id": "bob", "role": "user", "active": True},
            "admin": {"id": "admin", "role": "admin", "active": True},
        },
    }


def response(code=200, body=None):
    return {"status_code": code, "body": body if body is not None else {}, "error": None}


@pytest.mark.parametrize("change", [
    {"actor": "stranger"}, {"operation": "GET"}, {"resource": "https://example.com"},
    {"resource": "../bob-private-1"}, {"expected_allowed": "false"},
    {"split": "training"}, {"id": "bad\nheader"}, {"credentials": "secret"},
])
def test_matrix_rejects_unknown_or_unsafe_fields(change):
    with pytest.raises(ValueError):
        validate_matrix(matrix_with(matrix_case(**change)))


def test_matrix_rejects_duplicate_ids_and_unknown_top_fields():
    with pytest.raises(ValueError):
        validate_matrix(matrix_with(matrix_case(), matrix_case()))
    with pytest.raises(ValueError):
        validate_matrix({**matrix_with(), "target": "http://example.com"})


def test_matrix_validation_does_not_mutate_input():
    original = matrix_with()
    before = copy.deepcopy(original)
    assert validate_matrix(original) == before
    assert original == before


@pytest.mark.parametrize("case", [
    matrix_case(actor="bob", expected_allowed=False),
    matrix_case(expected_allowed=True),
    matrix_case(actor="guest", resource="alice-public", expected_allowed=False),
    matrix_case(actor="admin", operation="admin-read", resource="users", expected_allowed=False),
])
def test_matrix_cannot_relabel_owned_lab_permissions(case):
    with pytest.raises(ValueError, match="permission"):
        validate_matrix(matrix_with(case))


def test_matrix_load_is_bounded_and_validated(tmp_path):
    target = tmp_path / "matrix.json"
    target.write_text("{}")
    with pytest.raises(ValueError):
        load_matrix(target)
    target.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(ValueError):
        load_matrix(target)


def test_read_requires_exact_resource_and_private_content():
    before = state()
    case = matrix_case()
    assert evaluate_observation(case, response(body=before["documents"][case["resource"]]), before, before)["status"] == "violation"
    for body in ({}, {"id": "wrong", "content": "synthetic-bob-canary"}, {"id": case["resource"], "title": "Restricted"}):
        assert evaluate_observation(case, response(body=body), before, before)["status"] == "no_violation"


def test_denial_status_does_not_hide_private_data_leak():
    before = state()
    case = matrix_case()
    assert evaluate_observation(case, response(403, before["documents"][case["resource"]]), before, before)["status"] == "violation"


def test_write_requires_actual_effect_even_when_status_is_denied():
    before = state()
    after = copy.deepcopy(before)
    after["documents"]["bob-private-1"]["title"] = "test-update-marker"
    case = matrix_case(operation="update")
    assert evaluate_observation(case, response(200), before, before, marker="test-update-marker")["status"] == "no_violation"
    assert evaluate_observation(case, response(403), before, after, marker="test-update-marker")["status"] == "violation"


def test_admin_action_requires_observed_state_change():
    before = state()
    after = copy.deepcopy(before)
    after["users"]["bob"]["active"] = False
    case = matrix_case(operation="admin-disable", resource="bob")
    assert evaluate_observation(case, response(200), before, before)["status"] == "no_violation"
    assert evaluate_observation(case, response(403), before, after)["status"] == "violation"


@pytest.mark.parametrize("code", [301, 302, 401, 429, 500, 503])
def test_operational_responses_are_not_safe(code):
    assert evaluate_observation(matrix_case(), response(code), state(), state())["status"] == "inconclusive"


def test_invalid_response_or_missing_resource_is_inconclusive():
    assert evaluate_observation(matrix_case(), {"status_code": None, "body": None, "error": "timeout"}, state(), state())["status"] == "inconclusive"
    assert evaluate_observation(matrix_case(), response(), {"documents": {}, "users": {}}, state())["status"] == "inconclusive"


@pytest.mark.parametrize("operation,broken", [
    ("read", {"documents": {"bob-private-1": []}, "users": {}}),
    ("read", {"documents": {"bob-private-1": {"id": "bob-private-1", "content": None}}, "users": {}}),
    ("delete", {"documents": [], "users": {}}),
    ("admin-read", {"documents": {}, "users": {"admin": []}}),
    ("admin-disable", {"documents": {}, "users": {"bob": {"active": "yes"}}}),
])
def test_malformed_control_state_is_inconclusive(operation, broken):
    resource = "users" if operation == "admin-read" else "bob" if operation == "admin-disable" else "bob-private-1"
    assert evaluate_observation(matrix_case(operation=operation, resource=resource), response(), broken, broken)["status"] == "inconclusive"


def test_malformed_after_state_cannot_confirm_deletion():
    after = {**state(), "documents": []}
    assert evaluate_observation(matrix_case(operation="delete"), response(), state(), after)["status"] == "inconclusive"


def test_export_html_escapes_untrusted_error_text(tmp_path):
    report = {"kind": "bac-research", "run_id": "run", "results": [{"id": "case", "reason": "<script>alert(1)</script>"}]}
    exported = export_report(report, matrix_with(), tmp_path / "html")
    content = Path(exported["output_dir"]).joinpath("report.html").read_text()
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content


def test_allowed_control_failure_is_inconclusive_not_secure():
    case = matrix_case(actor="bob", expected_allowed=True)
    assert evaluate_observation(case, response(403), state(), state())["status"] == "inconclusive"


def test_verdict_does_not_use_mode_or_known_bug_labels():
    before = state()
    case = matrix_case()
    observation = response(body=before["documents"][case["resource"]])
    expected = evaluate_observation(case, observation, before, before)
    assert evaluate_observation({**case, "mode": "fixed", "known_vulnerable": False}, observation, before, before) == expected


def test_redaction_covers_nested_credentials_and_actual_values():
    value = {"Authorization": "Bearer test-token", "Cookie": "session=test-token", "nested": [
        {"password": "pw", "safe": "URL test-token", "api_key": "key", "Set-Cookie": "test-token"}
    ]}
    original = copy.deepcopy(value)
    redacted = redact(value, ("test-token",))
    assert value == original
    encoded = json.dumps(redacted)
    assert "test-token" not in encoded
    assert "\"pw\"" not in encoded
    assert redacted["Authorization"] == "[REDACTED]"


def test_redaction_removes_actual_tokens_used_as_json_keys():
    assert "test-token" not in json.dumps(redact({"test-token": {"message": "test-token"}}, ("test-token",)))


def test_repeated_trial_evidence_preserves_mode_and_repeat(tmp_path):
    report = {"kind": "bac-benchmark", "run_id": "benchmark", "results": [
        {**matrix_case(id="same-case"), "mode": mode, "repeat": repeat,
         "expected_violation": mode == "vulnerable", "prediction": "no_violation",
         "baseline_prediction": "no_violation",
         "evidence": {"server_events": [{"request_id": f"request-{mode}-{repeat}"}]}}
        for mode, repeat in (("fixed", 1), ("vulnerable", 1), ("fixed", 2))
    ]}
    exported = export_report(report, matrix_with(), tmp_path / "trials")
    assert exported["sample_counts"] == {
        "distinct_scenarios": 1, "distinct_mode_cases": 2, "attempted_observations": 3,
    }
    assert exported["metrics"]["enhanced"]["by_repeat"]["1"]["total"] == 2
    assert exported["metrics"]["enhanced"]["by_repeat"]["2"]["total"] == 1
    assert (tmp_path / "trials" / "metrics.csv").is_file()
    assert (tmp_path / "trials" / "case-results.csv").is_file()
    evidence = json.loads((tmp_path / "trials" / "evidence.json").read_text())
    assert {(item["mode"], item["repeat"]) for item in evidence} == {("fixed", 1), ("vulnerable", 1), ("fixed", 2)}
    events = json.loads((tmp_path / "trials" / "server-events.json").read_text())
    assert {(item["mode"], item["repeat"]) for item in events} == {("fixed", 1), ("vulnerable", 1), ("fixed", 2)}


def test_signed_export_has_no_fabricated_source_binding_and_tampering_fails(tmp_path):
    from app.cli_reports import run_verify_evidence

    report = {"kind": "bac-research", "run_id": "test-run", "status": "allowed", "exit_code": 0, "results": [], "findings": []}
    out = tmp_path / "evidence"
    exported = export_report(report, matrix_with(), out)
    assert "manifest_path" not in report
    manifest = json.loads(Path(exported["manifest_path"]).read_text())
    assert verify_manifest(manifest, evidence_public_key()["public_key"])
    assert "attestation" not in manifest.get("source", {})
    assert run_verify_evidence(str(out / "scan-manifest.json"), evidence_public_key()["public_key"]) == 0
    (out / "matrix.json").write_text("{}")
    assert run_verify_evidence(str(out / "scan-manifest.json"), evidence_public_key()["public_key"]) == 2


def test_export_refuses_existing_user_files_and_symlink(tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "notes.txt").write_text("keep me")
    with pytest.raises(ValueError):
        export_report({"results": []}, matrix_with(), existing)
    assert (existing / "notes.txt").read_text() == "keep me"
    link = tmp_path / "link"
    link.symlink_to(existing, target_is_directory=True)
    with pytest.raises(ValueError):
        export_report({"results": []}, matrix_with(), link)


@pytest.mark.parametrize("mode,expected,code", [("fixed", "no_violation", 0), ("vulnerable", "violation", 1)])
def test_live_research_detects_cross_user_access_and_exports_logs(tmp_path, mode, expected, code):
    result = run_research(mode=mode, matrix=matrix_with(), output_dir=tmp_path / mode)
    assert result["exit_code"] == code
    assert result["results"][0]["status"] == expected
    events = result["results"][0]["evidence"]["server_events"]
    assert any(event["actor"] == "alice" and event["case_id"] == "alice-cross-owner-read" for event in events)
    assert (tmp_path / mode / "report.html").exists()
    assert set(result["versions"]) == {"aegis", "python", "requests", "fastapi", "uvicorn", "implementation_sha256"}
    assert set(result["versions"]["implementation_sha256"]) == {
        "bac.py", "bac_config.py", "bac_lab.py", "bac_reports.py", "bac_benchmark.py",
    }
    assert all(len(digest) == 64 for digest in result["versions"]["implementation_sha256"].values())


def test_live_export_contains_no_ephemeral_credentials(tmp_path, monkeypatch):
    from contextlib import contextmanager
    import app.bac as bac

    original_lab = bac.local_bac_lab
    captured = []

    @contextmanager
    def capture_lab(mode):
        with original_lab(mode) as lab:
            captured.extend((*lab.tokens.values(), lab.control_token))
            yield lab

    monkeypatch.setattr(bac, "local_bac_lab", capture_lab)
    result = run_research(mode="vulnerable", matrix=matrix_with(), output_dir=tmp_path / "credentials")
    for artifact in Path(result["output_dir"]).iterdir():
        assert all(secret not in artifact.read_text() for secret in captured)


def test_live_preview_mask_is_not_a_violation(tmp_path):
    matrix = matrix_with(matrix_case(operation="preview"))
    result = run_research(mode="fixed", matrix=matrix, output_dir=tmp_path / "preview")
    assert result["results"][0]["http_status"] == 200
    assert result["results"][0]["status"] == "no_violation"


def test_invalid_matrix_never_starts_lab(tmp_path, monkeypatch):
    import app.bac as bac

    monkeypatch.setattr(bac, "local_bac_lab", lambda mode: pytest.fail("invalid matrix started a lab"))
    with pytest.raises(ValueError):
        run_research(mode="fixed", matrix=matrix_with(matrix_case(actor="unknown")), output_dir=tmp_path / "invalid")
