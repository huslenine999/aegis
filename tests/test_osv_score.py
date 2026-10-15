import json
import io
import time
from pathlib import Path

import pytest
import policy_engine
from app.dependencies import DependencyManifest, DependencyPackage
from policy_engine import parse_cvss_vector, calculate_exploitability_score as calculate_policy_score
from app.reporting import calculate_exploitability_score


def test_parse_cvss_vector_critical():
    # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H is CVSS 10.0 (Network, Low complexity, no privileges, no user interaction, Scope Changed, High confidentiality, integrity, availability)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    score = parse_cvss_vector(vector)
    assert score == 10.0

def test_parse_cvss_vector_high():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is CVSS 9.8 (Network, Low complexity, no privileges, no user interaction, Scope Unchanged, High C/I/A)
    vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = parse_cvss_vector(vector)
    assert score == 9.8

def test_parse_cvss_vector_medium():
    # AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L is CVSS 3.8
    vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
    score = parse_cvss_vector(vector)
    assert score == 3.8

def test_parse_cvss_vector_invalid():
    assert parse_cvss_vector("") == 0.0
    assert parse_cvss_vector("INVALID_VECTOR") == 0.0

def test_policy_exploitability_score_calculation():
    results = [
        {"tool": "Ruff (SAST)", "total_issues": 1, "blocking_issues": 1, "status": "FAIL", "severity_counts": {"HIGH": 1}, "examples": [
            {"severity": "HIGH", "issue_text": "SQL Injection"}
        ]},
        {"tool": "OSV Dependency Audit", "total_issues": 1, "blocking_issues": 1, "status": "FAIL", "severity_counts": {"HIGH": 1}, "examples": [
            {"package": "flask", "cvss": 7.5, "id": "CVE-2024-1234"}
        ]}
    ]
    # The score uses the worst severity plus a logarithmic volume bonus.
    score_waf_off = calculate_policy_score(results, False)
    assert score_waf_off == 89.0

    # WAF state does not discount unrelated static or dependency findings.
    score_waf_on = calculate_policy_score(results, True)
    assert score_waf_on == 89.0

def test_app_exploitability_score_calculation(tmp_path):
    # Setup mock scan reports in temp directory
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    
    # Write blank reports
    (scans_dir / "ruff-report.json").write_text(json.dumps([]))
    (scans_dir / "semgrep-report.json").write_text(json.dumps({"results": []}))
    (scans_dir / "secrets-report.json").write_text(json.dumps({"results": {}}))
    (scans_dir / "yara-report.json").write_text(json.dumps([]))
    (scans_dir / "osv-report.json").write_text(json.dumps([]))

    # Assert base score is 0.0 when no issues
    assert calculate_exploitability_score(scans_dir, False) == 0.0

    # A retired DAST artifact cannot affect a new score.
    (scans_dir / "ruff-report.json").write_text(json.dumps([
        {"code": "S608", "filename": "app.py", "location": {"row": 10}, "message": "SQL Injection"}
    ]))
    (scans_dir / "zap-report.json").write_text(json.dumps([
        {"status": "EXPOSED", "vuln_type": "SQL Injection", "route": "/user", "payload": "' OR 1=1", "description": "SQL Injection"}
    ]))

    # Only the active Ruff finding contributes.
    score_waf_off = calculate_exploitability_score(scans_dir, False)
    assert score_waf_off == 87.5

    # The WAF does not discount the independent static finding.
    score_waf_on = calculate_exploitability_score(scans_dir, True)
    assert score_waf_on == 87.5


def npm_manifest(*names):
    packages = tuple(DependencyPackage(name, "1.0.0", "npm") for name in names)
    return DependencyManifest(Path("package-lock.json"), "package-lock.json", "npm", packages)


def test_osv_batches_packages_and_fetches_each_advisory_once(fake_osv):
    names = [f"package-{i}" for i in range(8)]
    for i, name in enumerate(names[:6]):
        fake_osv.add("npm", name, "1.0.0", {"id": f"OSV-{i}", "aliases": [f"CVE-2026-{i}"]})
    shared = {"id": "OSV-shared"}
    fake_osv.add("npm", "package-6", "1.0.0", shared)
    fake_osv.add("npm", "package-7", "1.0.0", shared)

    findings = policy_engine.query_osv_vulnerabilities([npm_manifest(*names)], raise_on_error=True)

    assert len(fake_osv.batches) == 1 and len(fake_osv.batches[0]) == 8
    assert sorted(fake_osv.fetched) == sorted([f"OSV-{i}" for i in range(6)] + ["OSV-shared"])
    assert [(f["id"], f["package"]) for f in findings] == [
        *[(f"OSV-{i}", f"package-{i}") for i in range(6)],
        ("OSV-shared", "package-6"),
        ("OSV-shared", "package-7"),
    ]
    assert findings[0]["aliases"] == ["CVE-2026-0"]
    saved = json.loads(policy_engine.OSV_CACHE_FILE.read_text())
    assert {f"npm:{name}@1.0.0" for name in names} <= set(saved)
    assert "osv-advisory:OSV-shared" in saved


def test_osv_splits_large_inventories_into_bounded_batches(fake_osv, monkeypatch):
    monkeypatch.setattr(policy_engine, "OSV_BATCH_SIZE", 3)

    policy_engine.query_osv_vulnerabilities([npm_manifest(*[f"p{i}" for i in range(7)])], raise_on_error=True)

    assert [len(batch) for batch in fake_osv.batches] == [3, 3, 1]


def test_osv_follows_pagination_for_packages_with_many_advisories(fake_osv):
    fake_osv.page_size = 1
    fake_osv.add("npm", "busy", "1.0.0", {"id": "A"}, {"id": "B"}, {"id": "C"})
    fake_osv.add("npm", "quiet", "1.0.0", {"id": "D"})

    findings = policy_engine.query_osv_vulnerabilities([npm_manifest("busy", "quiet")], raise_on_error=True)

    assert [f["id"] for f in findings] == ["A", "B", "C", "D"]
    assert [len(batch) for batch in fake_osv.batches] == [2, 1, 1]
    assert fake_osv.batches[1][0]["page_token"] == "1"


def test_osv_reuses_cached_advisories_that_are_unmodified(fake_osv, monkeypatch):
    fake_osv.add("npm", "lib", "1.0.0", {"id": "OSV-1", "modified": "2026-05-01T00:00:00Z"})
    monkeypatch.setattr(policy_engine.time, "time", lambda: 1000)
    policy_engine.query_osv_vulnerabilities([npm_manifest("lib")], raise_on_error=True)
    # The package entry expires, so the batch query runs again ...
    monkeypatch.setattr(policy_engine.time, "time", lambda: 1000 + 90000)

    findings = policy_engine.query_osv_vulnerabilities([npm_manifest("lib")], raise_on_error=True)

    # ... but the unchanged advisory is not downloaded a second time.
    assert len(fake_osv.batches) == 2
    assert fake_osv.fetched == ["OSV-1"]
    assert findings[0]["id"] == "OSV-1"


def test_osv_advisory_ids_from_responses_cannot_change_the_request_path(fake_osv):
    fake_osv.add("npm", "lib", "1.0.0", {"id": "../../v1/admin?x=1"})

    policy_engine.query_osv_vulnerabilities([npm_manifest("lib")], raise_on_error=True)

    assert fake_osv.urls[-1] == "https://api.osv.dev/v1/vulns/..%2F..%2Fv1%2Fadmin%3Fx%3D1"


def test_osv_batch_merge_preserves_cache_ttl_stale_fallback_and_strict_failures(fake_osv, monkeypatch):
    policy_engine.OSV_CACHE_FILE.write_text(json.dumps({
        "npm:fresh@1.0.0": {"timestamp": 199999, "vulns": [{"id": "fresh"}]},
        "npm:stale@1.0.0": {"timestamp": 0, "vulns": [{"id": "stale"}]},
    }))
    fake_osv.add("npm", "stale", "1.0.0", {"id": "stale-new"})
    fake_osv.add("npm", "unavailable", "1.0.0", {"id": "down"})
    fake_osv.add("npm", "available", "1.0.0", {"id": "available"})
    fake_osv.failing = {"stale-new", "down"}
    monkeypatch.setattr(policy_engine.time, "time", lambda: 200000)
    manifest = npm_manifest("fresh", "stale", "unavailable", "available")

    findings = policy_engine.query_osv_vulnerabilities([manifest])

    assert [finding["id"] for finding in findings] == ["fresh", "stale", "available"]
    assert [query["package"]["name"] for query in fake_osv.batches[0]] == ["stale", "unavailable", "available"]
    saved = json.loads(policy_engine.OSV_CACHE_FILE.read_text())
    assert saved["npm:fresh@1.0.0"]["timestamp"] == 199999
    assert saved["npm:stale@1.0.0"]["timestamp"] == 0
    assert saved["npm:available@1.0.0"]["timestamp"] == 200000
    with pytest.raises(RuntimeError, match="npm:stale@1.0.0, npm:unavailable@1.0.0"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)


def test_osv_batch_outage_fails_every_uncached_package(fake_osv):
    fake_osv.batch_fails = True

    with pytest.raises(RuntimeError, match="npm:a@1.0.0, npm:b@1.0.0"):
        policy_engine.query_osv_vulnerabilities([npm_manifest("a", "b")], raise_on_error=True)
    assert fake_osv.fetched == []


def test_osv_batch_response_with_wrong_result_count_is_rejected(fake_osv, monkeypatch):
    monkeypatch.setattr(
        policy_engine.urllib.request, "urlopen",
        lambda *args, **kwargs: io.BytesIO(b'{"results": [{"vulns": []}]}'),
    )

    with pytest.raises(RuntimeError, match="OSV queries failed"):
        policy_engine.query_osv_vulnerabilities([npm_manifest("a", "b")], raise_on_error=True)


@pytest.mark.parametrize("payload", [b"{", b"x" * 33])
def test_osv_concurrent_response_errors_still_fail_strict_gates(tmp_path, monkeypatch, payload):
    cache = tmp_path / "osv-cache.json"
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", cache)
    monkeypatch.setenv("AEGIS_MAX_PARSER_INPUT_BYTES", "32")
    monkeypatch.setattr(policy_engine.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(payload))
    manifest = DependencyManifest(
        Path("requirements.txt"), "requirements.txt", "PyPI",
        (DependencyPackage("package", "1.0.0", "PyPI"),),
    )

    with pytest.raises(RuntimeError, match="OSV queries failed"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)
    assert not cache.exists()


def test_osv_interrupt_does_not_wait_for_in_flight_advisory_downloads(fake_osv, monkeypatch):
    sync_sleep = time.sleep
    for i in range(4):
        fake_osv.add("npm", f"package-{i}", "1.0.0", {"id": f"OSV-{i}"})

    class SlowResponse(io.BytesIO):
        def read1(self, size=-1):
            sync_sleep(0.6)
            return super().read1(size)

    def request(req, **kwargs):
        response = fake_osv(req, **kwargs)
        if req.full_url.endswith(("OSV-1", "OSV-2", "OSV-3")):
            return SlowResponse(response.getvalue())
        return response

    def interrupt(_vuln):
        raise KeyboardInterrupt

    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", request)
    monkeypatch.setattr(policy_engine, "_normalize_osv_advisory", interrupt)

    began = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        policy_engine.query_osv_vulnerabilities([npm_manifest(*[f"package-{i}" for i in range(4)])])

    assert time.monotonic() - began < 0.4
    assert len(fake_osv.fetched) >= 2


def test_osv_overall_deadline_stops_a_dribbling_response(tmp_path, monkeypatch):
    sync_sleep = time.sleep
    closed = []

    class DribblingResponse(io.BytesIO):
        def read1(self, size=-1):
            sync_sleep(0.02)
            return b" "

        def __exit__(self, *args):
            closed.append(True)

    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", lambda *args, **kwargs: DribblingResponse())
    monkeypatch.setattr(policy_engine, "OSV_REQUEST_DEADLINE_SECONDS", 0.05)
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", tmp_path / "osv-cache.json")
    manifest = DependencyManifest(
        Path("requirements.txt"), "requirements.txt", "PyPI",
        (DependencyPackage("package", "1.0.0", "PyPI"),),
    )

    began = time.monotonic()
    with pytest.raises(RuntimeError, match="OSV queries failed"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)
    assert time.monotonic() - began < 0.3
    assert closed == [True]


def test_osv_total_budget_fails_closed_instead_of_running_forever(fake_osv, monkeypatch):
    fake_osv.add("npm", "a", "1.0.0", {"id": "OSV-A"})
    monkeypatch.setattr(policy_engine, "OSV_BATCH_SIZE", 1)
    monkeypatch.setattr(policy_engine, "OSV_TOTAL_DEADLINE_SECONDS", -1.0)

    with pytest.raises(RuntimeError, match="npm:a@1.0.0, npm:b@1.0.0"):
        policy_engine.query_osv_vulnerabilities([npm_manifest("a", "b")], raise_on_error=True)
    assert fake_osv.batches == []
