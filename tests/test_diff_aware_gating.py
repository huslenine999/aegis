import json
import time
from pathlib import Path

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

    first = {
        "secrets": json.loads(json.dumps(SECRETS_REPORT)),
        "tools": [{"name": "Secrets", "status": "completed"}],
    }
    sync_findings(new_run(), first)
    assert project_baseline_fingerprints(project_id) == {
        item["fingerprint"] for item in extract_findings(first)
    }

    # A later complete scan no longer observes either finding: both resolve.
    sync_findings(
        new_run(),
        {
            "secrets": {"results": {}},
            "tools": [{"name": "Secrets", "status": "completed"}],
        },
    )
    baseline_after_resolution = project_baseline_fingerprints(project_id)
    assert baseline_after_resolution == set()

    # Reintroduce the same findings; against the empty baseline every one of
    # them is new, so the gate blocks on them again.
    reintroduced = {
        "secrets": json.loads(json.dumps(SECRETS_REPORT)),
        "tools": [{"name": "Secrets", "status": "completed"}],
    }
    observed = {item["fingerprint"] for item in extract_findings(reintroduced)}
    assert observed - baseline_after_resolution == observed

    # Once that scan completes, the findings are established baseline again
    # for any subsequent diff-aware scan.
    sync_findings(new_run(), reintroduced)
    assert observed <= project_baseline_fingerprints(project_id)


# --- A PR scan must never turn its own findings into baseline -------------------

LEAKED_KEY = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


def _pr_scan(tmp_path, monkeypatch, project_id, job_id, source, *, pull_request, diff_aware=True):
    from app import projects, worker
    from app.scan_engine import ScanJobPayload

    run_id = projects.create_scan_run(
        job_id=job_id, project_id=project_id, requested_by=10, target="project",
        preset="quick", github_pull_request=pull_request,
    )
    worker.async_scan_task(ScanJobPayload(
        job_id, "project", custom_file_path=str(source), scan_run_id=run_id,
        project_id=project_id, requested_by=10, preset="quick", diff_aware=diff_aware,
    ))
    return projects.get_scan_run(run_id)


def _scan_setup(tmp_path, monkeypatch):
    from app import projects, worker

    from tests.test_projects import configure_project_database

    configure_project_database(tmp_path, monkeypatch)
    monkeypatch.setattr(worker, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(worker, "redis_client", database.InMemoryRedis())
    monkeypatch.setattr(worker, "_source_revision", lambda _: "unavailable")
    monkeypatch.setattr(worker, "queue_project_notification", lambda *args: None)
    monkeypatch.setattr(worker, "_complete_github_scan_check", lambda *args: None)
    monkeypatch.setenv("AEGIS_ENABLE_YARA", "false")
    # detect-secrets runs for real; the other scanners report nothing.
    monkeypatch.setenv("AEGIS_SKIP_EXTERNAL_SCANNERS", "false")
    monkeypatch.setattr(worker, "query_osv_vulnerabilities", lambda *args, **kwargs: [], raising=False)

    def quiet_scanner(command, *args, **kwargs):
        output_path = Path(kwargs.get("stdout_output_path") or kwargs.get("output_path"))
        output_path.write_text('{"results": []}' if "semgrep" in output_path.name else "[]")
        return 0

    monkeypatch.setattr(worker, "execute_subprocess_log", quiet_scanner)
    monkeypatch.setattr(worker.time, "sleep", lambda *args: None)
    return projects.create_project(
        name="PR gate", repository_url="", github_full_name="", default_branch="main",
        scan_preset="quick", user_id=10,
    )


def _finding_rows(project_id):
    with database.get_connection() as connection:
        return connection.execute(
            "SELECT fingerprint, status FROM security_findings WHERE project_id = ?", (project_id,)
        ).fetchall()


def test_blocked_pr_stays_blocked_on_its_next_push(tmp_path, monkeypatch):
    project_id = _scan_setup(tmp_path, monkeypatch)
    source = tmp_path / "pr"
    source.mkdir()
    (source / "settings.py").write_text(LEAKED_KEY)

    first = _pr_scan(tmp_path, monkeypatch, project_id, "pr-7-push-1", source, pull_request=7)
    assert first["result"]["policy"]["status"] == "BLOCKED"
    assert first["new_findings"] == 1
    assert _finding_rows(project_id) == []

    # An unrelated commit does not fix anything, so the gate must still block.
    (source / "readme.txt").write_text("unrelated change\n")
    second = _pr_scan(tmp_path, monkeypatch, project_id, "pr-7-push-2", source, pull_request=7)
    assert second["result"]["policy"]["status"] == "BLOCKED"
    assert second["new_findings"] == 1

    # Another PR that adds the same problem is not exempted by PR #7 either.
    other = _pr_scan(tmp_path, monkeypatch, project_id, "pr-8-push-1", source, pull_request=8)
    assert other["result"]["policy"]["status"] == "BLOCKED"
    assert _finding_rows(project_id) == []


def test_pr_scan_does_not_resolve_project_findings(tmp_path, monkeypatch):
    project_id = _scan_setup(tmp_path, monkeypatch)
    main_tree = tmp_path / "main"
    main_tree.mkdir()
    (main_tree / "settings.py").write_text(LEAKED_KEY)
    _pr_scan(tmp_path, monkeypatch, project_id, "main-1", main_tree, pull_request=None, diff_aware=False)
    assert [row[1] for row in _finding_rows(project_id)] == ["open"]

    # The PR branch deletes the file; that says nothing about the project itself.
    branch = tmp_path / "branch"
    branch.mkdir()
    (branch / "readme.txt").write_text("no secrets here\n")
    pr = _pr_scan(tmp_path, monkeypatch, project_id, "pr-9-push-1", branch, pull_request=9)
    assert pr["result"]["policy"]["status"] == "ALLOWED"
    assert [row[1] for row in _finding_rows(project_id)] == ["open"]


def test_migration_027_removes_what_pr_scans_wrote(tmp_path, monkeypatch):
    from app import projects
    from app.findings import sync_findings

    project_id = _scan_setup(tmp_path, monkeypatch)
    secrets_tools = [{"name": "Secrets", "status": "completed"}]
    main_run = projects.create_scan_run(
        job_id="main", project_id=project_id, requested_by=10, target="project", preset="quick",
    )
    sync_findings(main_run, {"secrets": json.loads(json.dumps(SECRETS_REPORT)), "tools": secrets_tools})
    # What an old PR scan wrote: one PR-only finding, and a project finding it resolved.
    pr_run = projects.create_scan_run(
        job_id="pr", project_id=project_id, requested_by=10, target="project",
        preset="quick", github_pull_request=7,
    )
    pr_only = {"results": {"app/new.py": [{"type": "Secret Keyword", "line_number": 3}]}}
    with database.get_connection() as connection:
        connection.execute("UPDATE scan_runs SET github_pull_request = 7 WHERE id = ?", (pr_run,))
    sync_findings(pr_run, {"secrets": pr_only, "tools": secrets_tools})
    rows = dict(_finding_rows(project_id))
    assert sorted(rows.values()) == ["open", "resolved", "resolved"]

    with database.get_connection() as connection:
        cursor = connection.cursor()
        database._migration_027_remove_pull_request_findings(cursor)

    main_fingerprints = {item["fingerprint"] for item in extract_findings({"secrets": SECRETS_REPORT})}
    assert dict(_finding_rows(project_id)) == {fingerprint: "open" for fingerprint in main_fingerprints}
    with database.get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE scan_run_id = ?", (pr_run,)
        ).fetchone()[0] == 0
        assert {row[0] for row in connection.execute(
            "SELECT last_seen_run_id FROM security_findings WHERE project_id = ?", (project_id,)
        )} == {main_run}
