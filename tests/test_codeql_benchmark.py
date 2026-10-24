"""Scoring logic of scripts/run_codeql_benchmark.py, without CodeQL installed."""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("run_codeql_benchmark", ROOT / "scripts" / "run_codeql_benchmark.py")
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def write_corpus(tmp_path):
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"schema_version": 1, "cases": [
        {"id": "sqli", "file": "a.py", "expected_rule_id": "py/sql-injection", "source": "x = 1\n"},
        {"id": "safe-sql", "file": "b.py", "expected_rule_id": None, "source": "x = 2\n"},
        {"id": "cmd", "file": "c.js", "expected_rule_id": "js/command-line-injection", "source": "x\n"},
        {"id": "safe-cmd", "file": "d.js", "expected_rule_id": None, "source": "y\n"},
    ]}))
    return corpus


def test_scores_strict_target_class_semgrep_and_combined(tmp_path, monkeypatch):
    codeql = {
        "a.py": {"py/sql-injection"},
        "c.js": {"js/code-injection"},  # wrong query on a vulnerable case: a miss
        "d.js": {"js/missing-rate-limiting"},  # unrelated query on a safe case
    }
    semgrep = {"c.js": {"javascript-command-injection"}}
    monkeypatch.setattr(benchmark, "_direct_codeql", lambda *args: (codeql, {"runtime": "direct-cli"}))
    monkeypatch.setattr(benchmark, "_semgrep", lambda source: (semgrep, {"rules_sha256": "x"}))

    report = benchmark.run_benchmark(write_corpus(tmp_path), codeql_cli=Path("codeql"), with_semgrep=True)

    assert report["passed"] is False
    assert (report["metrics"]["true_positives"], report["metrics"]["false_positives"]) == (1, 1)
    # Unrelated queries do not count against the targeted vulnerability classes.
    assert report["codeql_target_class_metrics"]["false_positives"] == 0
    assert report["semgrep"]["metrics"]["true_positives"] == 1
    assert report["semgrep"]["combined_with_codeql"]["true_positives"] == 2
    assert report["semgrep"]["combined_with_codeql"]["recall"] == 1.0


def test_rejects_corpus_paths_outside_the_workspace(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"schema_version": 1, "cases": [
        {"id": "escape", "file": "../escape.py", "expected_rule_id": None, "source": ""},
    ]}))
    monkeypatch.setattr(benchmark, "_direct_codeql", lambda *args: ({}, {}))

    try:
        benchmark.run_benchmark(corpus, codeql_cli=Path("codeql"))
    except ValueError as error:
        assert "relative" in str(error)
    else:
        raise AssertionError("path traversal was accepted")


def test_repository_inventory_counts_triage_units_and_records_failures(tmp_path, monkeypatch):
    manifest = tmp_path / "repositories.json"
    manifest.write_text(json.dumps({"schema_version": 1, "repositories": [
        {"name": "app", "url": "https://example.com/app.git", "commit": "a" * 40, "kind": "application", "stack": "Flask"},
        {"name": "gone", "url": "https://example.com/gone.git", "commit": "b" * 40, "kind": "application", "stack": "Flask"},
    ]}))

    def checkout(url, commit, destination):
        if "gone" in url:
            raise subprocess.CalledProcessError(128, "git")
        destination.mkdir()

    codeql = {"a.py": {"py/sql-injection", "py/path-injection"}, "b.py": {"py/sql-injection"}}
    monkeypatch.setattr(benchmark, "_checkout", checkout)
    monkeypatch.setattr(benchmark, "_direct_codeql", lambda *args: (codeql, {"languages": ["python"]}))
    monkeypatch.setattr(benchmark, "_semgrep", lambda source, allow_errors: ({}, {"errors": 2}))

    report = benchmark.run_repositories(manifest, codeql_cli=Path("codeql"))

    app, gone = report["results"]
    assert app["codeql"] == {
        "flagged_files": 2, "file_rule_pairs": 3,
        "by_rule": {"py/path-injection": ["a.py"], "py/sql-injection": ["a.py", "b.py"]},
    }
    assert app["semgrep"]["errors"] == 2
    assert gone["status"] == "failed"
    assert (report["operational_failures"], report["passed"]) == (1, False)


def test_repository_checkout_requires_a_pinned_commit(tmp_path):
    with pytest.raises(ValueError):
        benchmark._checkout("https://example.com/app.git", "main", tmp_path / "branch")
