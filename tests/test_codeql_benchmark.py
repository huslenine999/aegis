"""Scoring logic of scripts/run_codeql_benchmark.py, without CodeQL installed."""

import importlib.util
import json
from pathlib import Path

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
