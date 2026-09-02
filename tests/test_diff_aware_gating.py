import json
import time

from app import database
from app.findings import (
    BASELINE_FINGERPRINT_KEY,
    extract_findings,
    project_baseline_fingerprints,
    strip_baseline_findings,
)
from policy_engine import run_policy_engine

from tests.test_hardening import configure_database


SECRETS_REPORT = {
    "results": {
        "app/config.py": [
            {"type": "Secret Keyword", "line_number": 10},
        ],
        "app/legacy.py": [
            {"type": "AWS Access Key", "line_number": 22},
        ],
    }
}


def _write_reports(scan_dir, secrets_report):
    (scan_dir / "secrets-report.json").write_text(json.dumps(secrets_report))
    empty_reports = {
        "ruff-report.json": [],
        "semgrep-report.json": {"results": []},
        "safety-report.json": [],
        "osv-report.json": [],
        "trivy-report.json": {"Results": []},
        "yara-report.json": [],
        "clamav-report.json": [],
        "zap-report.json": [],
        "iac-report.json": {"findings": []},
    }
    for name, payload in empty_reports.items():
        (scan_dir / name).write_text(json.dumps(payload))


def test_extract_findings_tags_raw_report_entries():
    result = {"secrets": SECRETS_REPORT}
    observed = extract_findings(result)
    tagged = {
        item[BASELINE_FINGERPRINT_KEY]
        for items in result["secrets"]["results"].values()
        for item in items
    }
    assert len(tagged) == 2
    assert tagged == {item["fingerprint"] for item in observed}


def test_strip_baseline_removes_only_matching_entries():
    result = {"secrets": SECRETS_REPORT}
    fingerprints = [item["fingerprint"] for item in extract_findings(result)]
    baseline = {fingerprints[0]}

    filtered, exempted = strip_baseline_findings(
        json.loads(json.dumps(SECRETS_REPORT)), baseline
    )

    assert exempted == 1
    remaining = [item for items in filtered["results"].values() for item in items]
    assert len(remaining) == 1
    assert remaining[0][BASELINE_FINGERPRINT_KEY] not in baseline


def test_strip_baseline_keeps_untagged_entries_fail_closed():
    untagged_report = {
        "results": {
            "app/config.py": [{"type": "Secret Keyword", "line_number": 10}]
        }
    }
    filtered, exempted = strip_baseline_findings(untagged_report, {"deadbeef"})
    assert exempted == 0
    assert filtered["results"]["app/config.py"]


def test_run_policy_engine_excludes_baseline_findings(tmp_path):
    _write_reports(tmp_path, json.loads(json.dumps(SECRETS_REPORT)))
    tagged = extract_findings({"secrets": json.loads(json.dumps(SECRETS_REPORT))})
    baseline = {item["fingerprint"] for item in tagged}

    exit_code = run_policy_engine(
        tmp_path,
        md_path=tmp_path / "report.md",
        html_path=tmp_path / "report.html",
        baseline_fingerprints=baseline,
    )
    assert exit_code == 0


def test_run_policy_engine_still_blocks_new_findings_with_baseline(tmp_path):
    _write_reports(tmp_path, json.loads(json.dumps(SECRETS_REPORT)))
    known = extract_findings({"secrets": json.loads(json.dumps(SECRETS_REPORT))})
    baseline = {known[0]["fingerprint"]}  # one known, one new

    exit_code = run_policy_engine(
        tmp_path,
        md_path=tmp_path / "report.md",
        html_path=tmp_path / "report.html",
        baseline_fingerprints=baseline,
    )
    assert exit_code == 1


def test_project_baseline_excludes_resolved_findings(tmp_path, monkeypatch):
    from app import projects
    from app.findings import sync_findings

    from tests.test_hardening import add_user

    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        owner_id = add_user(connection, "diff-owner", "admin", tenant_id)

    project_id = projects.create_project(
        name="Diff",
        repository_url="https://github.com/example/diff.git",
        github_full_name="example/diff",
        default_branch="main",
        scan_preset="standard",
        user_id=owner_id,
    )

    def new_run() -> int:
        return projects.create_scan_run(
            job_id=f"job-{project_id}-{time.time_ns()}",
            project_id=project_id,
            requested_by=owner_id,
            target="project",
            preset="standard",
        )

    first = {"secrets": json.loads(json.dumps(SECRETS_REPORT))}
    sync_findings(new_run(), first)
    assert project_baseline_fingerprints(project_id) == {
        item["fingerprint"] for item in extract_findings(first)
    }

    # A later complete scan no longer observes either finding: both resolve.
    sync_findings(new_run(), {"secrets": {"results": {}}})
    baseline_after_resolution = project_baseline_fingerprints(project_id)
    assert baseline_after_resolution == set()

    # Reintroduce the same findings; against the empty baseline every one of
    # them is new, so the gate blocks on them again.
    reintroduced = {"secrets": json.loads(json.dumps(SECRETS_REPORT))}
    observed = {item["fingerprint"] for item in extract_findings(reintroduced)}
    assert observed - baseline_after_resolution == observed

    # Once that scan completes, the findings are established baseline again
    # for any subsequent diff-aware scan.
    sync_findings(new_run(), reintroduced)
    assert observed <= project_baseline_fingerprints(project_id)