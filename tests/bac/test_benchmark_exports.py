"""Benchmark publication artifacts, using synthetic observations unless marked live."""

import copy
import csv
import hashlib
import html
import json
import re
from pathlib import Path

import pytest

from app.bac_benchmark import classification_metrics, run_benchmark
from app.bac_imports import BAC_ARTIFACTS, validate_bac_bundle
from app.bac_reports import export_report
from app.cli_reports import run_verify_evidence
from app.evidence import canonical_json, evidence_public_key, verify_manifest


INDIVIDUAL_FILES = {
    "report.json", "matrix.json", "findings.json", "evidence.json", "server-events.json",
    "report.md", "report.html", "scan-manifest.json",
}
BENCHMARK_FILES = INDIVIDUAL_FILES | {"metrics.csv", "case-results.csv"}
METRIC_FIELDS = (
    "total", "scored", "inconclusive", "tp", "fp", "tn", "fn", "coverage",
    "precision", "recall", "false_positive_rate", "accuracy",
)
CASE_FIELDS = (
    "trial_run_id", "mode", "repeat", "id", "split", "actor", "operation", "resource",
    "expected_allowed", "expected_violation", "prediction", "baseline_prediction",
    "differential_prediction", "content_leak_prediction", "http_status", "duration_seconds", "reason",
)
SAMPLE_COUNTS = {"distinct_scenarios": 3, "distinct_mode_cases": 4, "attempted_observations": 6}


def benchmark_input():
    fields = ("id", "mode", "repeat", "operation", "split", "expected_violation",
              "prediction", "baseline_prediction")
    rows = [dict(zip(fields, values)) for values in [
        ("cross-read", "vulnerable", 1, "read", "evaluation", True, "violation", "violation"),
        ("guest-preview", "fixed", 1, "preview", "evaluation", False, "violation", "no_violation"),
        ("cross-read", "fixed", 1, "read", "evaluation", False, "no_violation", "violation"),
        ("cross-preview", "vulnerable", 2, "preview", "development", True, "no_violation", "violation"),
        ("cross-read", "vulnerable", 2, "read", "evaluation", True, "inconclusive", "inconclusive"),
        ("guest-preview", "fixed", 2, "preview", "evaluation", False, "inconclusive", "inconclusive"),
    ]]
    rows = [{
        **row, "actor": "guest" if row["id"] == "guest-preview" else "alice",
        "resource": "bob-private-2", "expected_allowed": False, "status": row["prediction"],
        "trial_run_id": None if index == 4 else f"trial-{row['mode']}-{row['repeat']}",
        "http_status": None if row["prediction"] == "inconclusive" else 200,
        "duration_seconds": 1 / 7, "reason": "Observed, paired\nresult.", "evidence": {},
    } for index, row in enumerate(rows)]
    cases = {row["id"]: {key: row[key] for key in (
        "id", "split", "actor", "operation", "resource", "expected_allowed",
    )} for row in rows}
    matrix = {"schema_version": 1, "corpus_id": "export-test-v1",
              "description": "Owned synthetic test corpus.", "cases": list(cases.values())}
    report = {
        "schema_version": 1, "kind": "bac-benchmark", "run_id": "benchmark-export-1",
        "corpus_id": matrix["corpus_id"], "matrix_sha256": hashlib.sha256(canonical_json(matrix)).hexdigest(),
        "started_at": "2026-10-08T01:00:00+00:00", "completed_at": "2026-10-08T01:01:00+00:00",
        "split": "all", "repeats": 2, "results": rows, "runs": [], "findings": [],
        "status": "error", "exit_code": 2, "runtime": {"wall_seconds": 1.0, "case_seconds": 6 / 7},
        "metrics": {"stale-cached-measurement": 999999},
        "sample_counts": {"distinct_scenarios": 999999, "attempted_observations": 999999},
        "metadata": {"baseline": "http-status-only", "baseline_kind": "same-trace ablation"},
        "operational_errors": [],
    }
    return report, matrix


def read_csv(directory, name):
    with (directory / name).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        return reader.fieldnames, list(reader)


def test_benchmark_export_recalculates_stale_measurements_without_mutating_inputs(tmp_path):
    report, matrix = benchmark_input()
    originals = copy.deepcopy((report, matrix))

    exported = export_report(report, matrix, tmp_path / "export")

    assert (report, matrix) == originals
    assert exported["sample_counts"] == SAMPLE_COUNTS
    assert exported["metrics"]["enhanced"]["overall"] == {
        "total": 6, "scored": 4, "inconclusive": 2, "tp": 1, "fp": 1, "tn": 1, "fn": 1,
        "coverage": 2 / 3, "precision": 0.5, "recall": 0.5,
        "false_positive_rate": 0.5, "accuracy": 0.5,
    }
    assert exported["metrics"]["http-status-only"]["overall"]["precision"] == 2 / 3
    directory = Path(exported["output_dir"])
    assert json.loads((directory / "report.json").read_text()) == exported
    for name in ("report.json", "report.md", "report.html", "metrics.csv"):
        content = (directory / name).read_text()
        assert "stale-cached-measurement" not in content
        assert "999999" not in content


def test_benchmark_csv_covers_every_group_and_preserves_full_precision_and_identity(tmp_path):
    report, matrix = benchmark_input()
    exported = export_report(report, matrix, tmp_path / "export")
    directory = Path(exported["output_dir"])
    fields, metric_rows = read_csv(directory, "metrics.csv")
    assert {"benchmark_run_id", "corpus_id", "matrix_sha256", "method", "group", "group_value", *METRIC_FIELDS} <= set(fields)
    expected = {}
    for method, prediction_key in (("enhanced", "prediction"), ("http-status-only", "baseline_prediction")):
        rows = [{**row, "prediction": row[prediction_key]} for row in report["results"]]
        expected[(method, "overall", "all")] = classification_metrics(rows)
        for field in ("mode", "operation", "split", "repeat"):
            for value in {row[field] for row in rows}:
                expected[(method, field, str(value))] = classification_metrics([row for row in rows if row[field] == value])
    assert len(metric_rows) == len(expected)
    assert {(row["method"], row["group"], row["group_value"]) for row in metric_rows} == set(expected)
    for row in metric_rows:
        metrics = expected[(row["method"], row["group"], row["group_value"])]
        assert {field: row[field] for field in METRIC_FIELDS} == {
            field: "" if metrics[field] is None else str(metrics[field]) for field in METRIC_FIELDS
        }
        for field, count in SAMPLE_COUNTS.items():
            if field in row:
                assert row[field] == str(count)
        for csv_key, report_key in (("benchmark_run_id", "run_id"), ("corpus_id", "corpus_id"), ("matrix_sha256", "matrix_sha256")):
            assert row[csv_key] == report[report_key]

    fields, case_rows = read_csv(directory, "case-results.csv")
    assert {"benchmark_run_id", "corpus_id", "matrix_sha256", *CASE_FIELDS} <= set(fields)
    assert len(case_rows) == len(report["results"])
    for row, observation in zip(case_rows, report["results"]):
        for field in CASE_FIELDS:
            expected_value = observation.get(field)
            assert row[field].lower() == ("" if expected_value is None else str(expected_value).lower())
        assert row["benchmark_run_id"] == report["run_id"]
        assert row["corpus_id"] == report["corpus_id"]
        assert row["matrix_sha256"] == report["matrix_sha256"]
    assert case_rows[4]["trial_run_id"] == ""
    assert case_rows[4]["http_status"] == ""


def test_undefined_rates_remain_null_in_json_blank_in_csv_and_readable_in_tables(tmp_path):
    report, matrix = benchmark_input()
    report = {**report, "results": [report["results"][4]]}
    exported = export_report(report, matrix, tmp_path / "export")
    directory = Path(exported["output_dir"])
    stored = json.loads((directory / "report.json").read_text())
    fields = ("precision", "recall", "false_positive_rate", "accuracy")
    for method in ("enhanced", "http-status-only"):
        assert {field: stored["metrics"][method]["overall"][field] for field in fields} == dict.fromkeys(fields)
        assert stored["metrics"][method]["overall"]["coverage"] == 0.0
    _, rows = read_csv(directory, "metrics.csv")
    for row in rows:
        assert all(row[field] == "" for field in fields)
    markdown = (directory / "report.md").read_text()
    document = (directory / "report.html").read_text()
    table_lines = [line for line in markdown.splitlines() if line.lstrip().startswith("|")]
    assert any("enhanced" in line and "undefined" in line.lower() for line in table_lines)
    assert any("http-status-only" in line and "undefined" in line.lower() for line in table_lines)
    tables = re.findall(r"<table\b[^>]*>.*?</table>", document, flags=re.DOTALL)
    assert any("enhanced" in table and "http-status-only" in table and "undefined" in table.lower() for table in tables)


def test_comparison_tables_show_sample_counts_and_evaluation_scope(tmp_path):
    report, matrix = benchmark_input()
    exported = export_report(report, matrix, tmp_path / "export")
    directory = Path(exported["output_dir"])
    for name in ("report.md", "report.html"):
        document = (directory / name).read_text()
        visible = html.unescape(re.sub(r"<[^>]*>", " ", document)).lower()
        visible = re.sub(r"\\(.)", r"\1", visible)
        for label in ("distinct scenarios", "distinct mode cases", "attempted observations"):
            assert label in visible
        for warning in ("same-trace ablation", "one synthetic lab corpus", "not independent samples"):
            assert warning in visible
        for label in ("precision", "recall", "accuracy", "coverage"):
            assert label in visible


def test_benchmark_redacts_secret_fields_in_all_artifacts_without_mutating_inputs(tmp_path):
    report, matrix = benchmark_input()
    synthetic_value = "synthetic-do-not-export-credential"
    report["metadata"] = {**report["metadata"], "client-secret": synthetic_value, "nested": [{"access_token": synthetic_value}]}
    report["results"][0]["evidence"] = {"headers": {"Authorization": synthetic_value, "Set-Cookie": synthetic_value}, "nested": [{"api-key": synthetic_value}]}
    matrix["control_token"] = synthetic_value
    originals = copy.deepcopy((report, matrix))

    exported = export_report(report, matrix, tmp_path / "export")

    assert (report, matrix) == originals
    directory = Path(exported["output_dir"])
    assert all(synthetic_value.encode() not in path.read_bytes() for path in directory.iterdir())
    assert exported["metadata"]["client-secret"] == "[REDACTED]"
    assert exported["results"][0]["evidence"]["headers"]["Authorization"] == "[REDACTED]"


@pytest.mark.parametrize("formula", [
    "=SUM(1,2)", "+SUM(1,2)", "-SUM(1,2)", "@SUM(1,2)",
    " \t=SUM(1,2)", "\r\n+SUM(1,2)", "\x00\x01@SUM(1,2)", "\x7f-1+1",
])
def test_csv_neutralizes_formulas_after_whitespace_or_controls_and_json_keeps_originals(tmp_path, formula):
    report, matrix = benchmark_input()
    report["run_id"] = report["corpus_id"] = formula
    changed_fields = ("trial_run_id", "id", "mode", "split", "actor", "operation", "resource", "reason")
    report["results"][0] = {**report["results"][0], **dict.fromkeys(changed_fields, formula)}
    originals = copy.deepcopy((report, matrix))

    exported = export_report(report, matrix, tmp_path / "export")

    assert (report, matrix) == originals
    directory = Path(exported["output_dir"])
    stored = json.loads((directory / "report.json").read_text())
    assert stored["run_id"] == stored["corpus_id"] == formula
    assert all(stored["results"][0][field] == formula for field in changed_fields)
    _, cases = read_csv(directory, "case-results.csv")
    assert all(cases[0][field] == "'" + formula for field in (*changed_fields, "benchmark_run_id", "corpus_id"))
    _, metrics = read_csv(directory, "metrics.csv")
    assert all(row["benchmark_run_id"] == row["corpus_id"] == "'" + formula for row in metrics)
    assert "'" + formula in {row["group_value"] for row in metrics}


def test_benchmark_html_and_markdown_escape_untrusted_table_and_link_content(tmp_path):
    report, matrix = benchmark_input()
    untrusted = '[owned](https://attacker.example) | <img src=x onerror="alert(1)">\n# forged'
    report["run_id"] = untrusted
    report["results"][0] = {**report["results"][0], **dict.fromkeys(("id", "actor", "operation", "reason"), untrusted)}
    exported = export_report(report, matrix, tmp_path / "export")
    directory = Path(exported["output_dir"])
    markdown = (directory / "report.md").read_text()
    document = (directory / "report.html").read_text()
    assert "<img src=x" not in document
    assert "&lt;img src=x" in document
    assert "<img src=x" not in markdown
    assert "[owned](https://attacker.example)" not in markdown
    assert "\n# forged" not in markdown
    assert r"\|" in markdown or "&#124;" in markdown or "&vert;" in markdown
    assert json.loads((directory / "report.json").read_text())["results"][0]["reason"] == untrusted


@pytest.mark.parametrize("kind, expected_files", [("bac-benchmark", BENCHMARK_FILES), ("bac-research", INDIVIDUAL_FILES)])
def test_exports_sign_exact_inventory_and_real_verifier_accepts_it(tmp_path, kind, expected_files):
    report, matrix = benchmark_input()
    report = {**report, "kind": kind}
    exported = export_report(report, matrix, tmp_path / "export")
    directory = Path(exported["output_dir"])
    assert {path.name for path in directory.iterdir()} == expected_files
    manifest = json.loads(Path(exported["manifest_path"]).read_text())
    inventory = manifest["artifacts"]
    assert len(inventory) == len(expected_files) - 1
    assert {item["name"] for item in inventory} == expected_files - {"scan-manifest.json"}
    for item in inventory:
        content = (directory / item["name"]).read_bytes()
        assert item["size"] == len(content)
        assert item["sha256"] == hashlib.sha256(content).hexdigest()
    key = evidence_public_key()["public_key"]
    assert verify_manifest(manifest, key)
    assert manifest["source_attestation"] == "not-claimed"
    assert run_verify_evidence(exported["manifest_path"], key) == 0


@pytest.mark.parametrize("name", ["metrics.csv", "case-results.csv"])
def test_csv_tampering_fails_real_evidence_verifier(tmp_path, name, capsys):
    report, matrix = benchmark_input()
    exported = export_report(report, matrix, tmp_path / "export")
    directory = Path(exported["output_dir"])
    path = directory / name
    assert path.is_file()
    key = evidence_public_key()["public_key"]
    assert run_verify_evidence(exported["manifest_path"], key) == 0
    path.write_bytes(path.read_bytes() + b"forged observation\n")
    assert run_verify_evidence(exported["manifest_path"], key) == 2
    assert name in capsys.readouterr().err


def test_dashboard_bundle_admission_keeps_eight_files_and_rejects_benchmark(tmp_path):
    report, matrix = benchmark_input()
    exported = export_report(report, matrix, tmp_path / "export")
    directory = Path(exported["output_dir"])
    artifacts = {path.name: path.read_bytes() for path in directory.iterdir()}
    assert set(BAC_ARTIFACTS) == INDIVIDUAL_FILES
    assert set(artifacts) == BENCHMARK_FILES
    with pytest.raises(ValueError, match="eight|individual|inventory"):
        validate_bac_bundle(artifacts, evidence_public_key()["public_key"])


def test_live_owned_loopback_benchmark_exports_agreement_and_masked_preview_ablation(tmp_path):
    matrix = {
        "schema_version": 1, "corpus_id": "export-loopback-v1", "description": "Owned loopback smoke corpus.",
        "cases": [{"id": f"cross-{operation}", "split": "evaluation", "actor": "alice", "operation": operation,
                   "resource": "bob-private-2", "expected_allowed": False} for operation in ("read", "preview")],
    }

    report = run_benchmark(matrix=matrix, split="evaluation", repeats=2, output_dir=tmp_path)

    assert report["exit_code"] == 0
    overall = report["metrics"]["enhanced"]["overall"]
    assert (overall["tp"], overall["tn"], overall["fp"], overall["fn"], overall["inconclusive"]) == (4, 4, 0, 0, 0)
    assert report["metrics"]["http-status-only"]["by_operation"]["preview"]["fp"] == 2
    assert report["sample_counts"] == {"distinct_scenarios": 2, "distinct_mode_cases": 4, "attempted_observations": 8}
    directory = Path(report["output_dir"])
    assert len(read_csv(directory, "case-results.csv")[1]) == 8
    assert read_csv(directory, "metrics.csv")[1]
    assert run_verify_evidence(report["manifest_path"], evidence_public_key()["public_key"]) == 0
