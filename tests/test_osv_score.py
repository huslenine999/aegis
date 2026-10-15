import json
import io
import threading
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


def test_osv_requests_overlap_with_bounded_concurrency_and_ordered_results(tmp_path, monkeypatch):
    barrier = threading.Barrier(4)
    lock = threading.Lock()
    active = 0
    peak = 0
    owner_thread = threading.get_ident()
    pacing_threads = []

    class Response(io.BytesIO):
        def __exit__(self, *args):
            nonlocal active
            with lock:
                active -= 1
            self.close()

    def request(req, **kwargs):
        nonlocal active, peak
        name = json.loads(req.data)["package"]["name"]
        index = int(name.rsplit("-", 1)[1])
        with lock:
            active += 1
            peak = max(peak, active)
        if index < 4:
            barrier.wait(timeout=1)
        return Response(json.dumps({"vulns": [{"id": f"OSV-{index}"}]}).encode())

    def pace(seconds):
        assert seconds == 0.1
        pacing_threads.append(threading.get_ident())

    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", request)
    monkeypatch.setattr(policy_engine.time, "sleep", pace)
    cache = tmp_path / "osv-cache.json"
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", cache)
    packages = tuple(DependencyPackage(f"package-{i}", "1.0.0", "npm") for i in range(8))
    manifest = DependencyManifest(Path("package-lock.json"), "package-lock.json", "npm", packages)

    findings = policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)

    assert peak == 4
    assert [finding["id"] for finding in findings] == [f"OSV-{i}" for i in range(8)]
    assert pacing_threads == [owner_thread] * 7
    saved = json.loads(cache.read_text())
    assert set(saved) == {f"npm:package-{i}@1.0.0" for i in range(8)}


def test_osv_concurrent_merge_preserves_cache_ttl_stale_fallback_and_strict_failures(tmp_path, monkeypatch):
    cache = tmp_path / "osv-cache.json"
    cache.write_text(json.dumps({
        "npm:fresh@1.0.0": {"timestamp": 199999, "vulns": [{"id": "fresh"}]},
        "npm:stale@1.0.0": {"timestamp": 0, "vulns": [{"id": "stale"}]},
    }))
    requested = []

    def request(req, **kwargs):
        name = json.loads(req.data)["package"]["name"]
        requested.append(name)
        if name != "available":
            raise TimeoutError("offline")
        return io.BytesIO(json.dumps({"vulns": [{"id": "available"}]}).encode())

    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", cache)
    monkeypatch.setattr(policy_engine.time, "time", lambda: 200000)
    monkeypatch.setattr(policy_engine.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", request)
    packages = tuple(DependencyPackage(name, "1.0.0", "npm") for name in ("fresh", "stale", "unavailable", "available"))
    manifest = DependencyManifest(Path("package-lock.json"), "package-lock.json", "npm", packages)

    findings = policy_engine.query_osv_vulnerabilities([manifest])

    assert [finding["id"] for finding in findings] == ["fresh", "stale", "available"]
    assert "fresh" not in requested
    saved = json.loads(cache.read_text())
    assert saved["npm:fresh@1.0.0"]["timestamp"] == 199999
    assert saved["npm:stale@1.0.0"]["timestamp"] == 0
    assert saved["npm:available@1.0.0"]["timestamp"] == 200000
    with pytest.raises(RuntimeError, match="npm:stale@1.0.0, npm:unavailable@1.0.0"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)


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


def test_osv_interrupt_does_not_wait_for_in_flight_requests(tmp_path, monkeypatch):
    sync_sleep = time.sleep
    started = []
    pauses = 0

    class SlowResponse(io.BytesIO):
        def read1(self, size=-1):
            sync_sleep(0.6)
            return super().read1(size)

    def request(req, **kwargs):
        started.append(json.loads(req.data)["package"]["name"])
        return SlowResponse(b'{"vulns": []}')

    def pace(seconds):
        nonlocal pauses
        pauses += 1
        if pauses == 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", request)
    monkeypatch.setattr(policy_engine.time, "sleep", pace)
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", tmp_path / "osv-cache.json")
    packages = tuple(DependencyPackage(f"package-{i}", "1.0.0", "npm") for i in range(4))
    manifest = DependencyManifest(Path("package-lock.json"), "package-lock.json", "npm", packages)

    began = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        policy_engine.query_osv_vulnerabilities([manifest])

    assert time.monotonic() - began < 0.3
    assert len(started) >= 2


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
