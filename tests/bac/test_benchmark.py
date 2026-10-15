import copy
import sys
import types
from pathlib import Path

import pytest

from app.bac_benchmark import (
    classification_metrics,
    expected_violation,
    run_benchmark,
    status_only_prediction,
)


def test_metrics_keep_inconclusive_results_out_of_confusion_counts():
    rows = [
        {"expected_violation": True, "prediction": "violation"},
        {"expected_violation": False, "prediction": "violation"},
        {"expected_violation": False, "prediction": "no_violation"},
        {"expected_violation": True, "prediction": "no_violation"},
        {"expected_violation": True, "prediction": "inconclusive"},
        {"expected_violation": False, "prediction": "inconclusive"},
    ]
    original = copy.deepcopy(rows)

    metrics = classification_metrics(rows)

    assert metrics == {
        "total": 6, "scored": 4, "inconclusive": 2,
        "tp": 1, "fp": 1, "tn": 1, "fn": 1,
        "coverage": pytest.approx(4 / 6),
        "precision": 0.5, "recall": 0.5,
        "false_positive_rate": 0.5, "accuracy": 0.5,
    }
    assert rows == original


@pytest.mark.parametrize(
    "rows, expected",
    [
        ([], {"coverage": None, "precision": None, "recall": None,
              "false_positive_rate": None, "accuracy": None}),
        ([{"expected_violation": True, "prediction": "inconclusive"}],
         {"coverage": 0.0, "precision": None, "recall": None,
          "false_positive_rate": None, "accuracy": None}),
        ([{"expected_violation": False, "prediction": "no_violation"}],
         {"coverage": 1.0, "precision": None, "recall": None,
          "false_positive_rate": 0.0, "accuracy": 1.0}),
    ],
)
def test_metrics_use_null_for_undefined_rates(rows, expected):
    metrics = classification_metrics(rows)
    assert {key: metrics[key] for key in expected} == expected


def test_benchmark_measurements_group_independent_confusion_fixture_without_mutation():
    from app.bac_benchmark import benchmark_measurements

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
    original = copy.deepcopy(rows)

    measurements = benchmark_measurements(rows)

    assert rows == original
    assert measurements["sample_counts"] == {
        "distinct_scenarios": 3, "distinct_mode_cases": 4, "attempted_observations": 6,
    }
    assert measurements["metrics"]["enhanced"]["overall"] == {
        "total": 6, "scored": 4, "inconclusive": 2, "tp": 1, "fp": 1, "tn": 1, "fn": 1,
        "coverage": pytest.approx(2 / 3), "precision": 0.5, "recall": 0.5,
        "false_positive_rate": 0.5, "accuracy": 0.5,
    }
    assert measurements["metrics"]["http-status-only"]["overall"] == {
        "total": 6, "scored": 4, "inconclusive": 2, "tp": 2, "fp": 1, "tn": 1, "fn": 0,
        "coverage": pytest.approx(2 / 3), "precision": pytest.approx(2 / 3), "recall": 1.0,
        "false_positive_rate": 0.5, "accuracy": 0.75,
    }
    expected_groups = {
        "enhanced": {
            "by_mode": {"fixed": (0, 1, 1, 0, 1), "vulnerable": (1, 0, 0, 1, 1)},
            "by_operation": {"read": (1, 0, 1, 0, 1), "preview": (0, 1, 0, 1, 1)},
            "by_split": {"development": (0, 0, 0, 1, 0), "evaluation": (1, 1, 1, 0, 2)},
            "by_repeat": {"1": (1, 1, 1, 0, 0), "2": (0, 0, 0, 1, 2)},
        },
        "http-status-only": {
            "by_mode": {"fixed": (0, 1, 1, 0, 1), "vulnerable": (2, 0, 0, 0, 1)},
            "by_operation": {"read": (1, 1, 0, 0, 1), "preview": (1, 0, 1, 0, 1)},
            "by_split": {"development": (1, 0, 0, 0, 0), "evaluation": (1, 1, 1, 0, 2)},
            "by_repeat": {"1": (1, 1, 1, 0, 0), "2": (1, 0, 0, 0, 2)},
        },
    }
    for method, expected in expected_groups.items():
        grouped = measurements["metrics"][method]
        assert set(grouped) == {"overall", *expected}
        for group, counts in expected.items():
            assert set(grouped[group]) == set(counts)
            for key, confusion in counts.items():
                metric = grouped[group][key]
                assert tuple(metric[field] for field in ("tp", "fp", "tn", "fn", "inconclusive")) == confusion
                assert metric["total"] == sum(confusion)
                assert metric["scored"] == sum(confusion[:4])
    assert measurements["metrics"]["enhanced"]["by_mode"]["fixed"]["recall"] is None
    assert measurements["metrics"]["enhanced"]["by_repeat"]["2"]["precision"] is None


@pytest.mark.parametrize(
    "row",
    [
        {"expected_violation": 1, "prediction": "violation"},
        {"expected_violation": False, "prediction": "safe"},
        {"expected_violation": False, "prediction": {"status": "violation"}},
        {"prediction": "violation"},
    ],
)
def test_metrics_reject_invalid_labels(row):
    with pytest.raises(ValueError):
        classification_metrics([row])


@pytest.mark.parametrize(
    "mode, allowed, actor, expected",
    [
        ("fixed", False, "alice", False),
        ("vulnerable", False, "alice", True),
        ("vulnerable", False, "guest", False),
        ("vulnerable", True, "bob", False),
    ],
)
def test_ground_truth_applies_only_to_known_lab_bugs(mode, allowed, actor, expected):
    assert expected_violation(mode, {"expected_allowed": allowed, "actor": actor}) is expected


@pytest.mark.parametrize(
    "allowed, status, http_status, expected",
    [
        (False, "violation", 200, "violation"),
        (False, "no_violation", 200, "violation"),
        (False, "no_violation", 403, "no_violation"),
        (True, "no_violation", 200, "no_violation"),
        (False, "inconclusive", 200, "inconclusive"),
        (False, "inconclusive", None, "inconclusive"),
    ],
)
def test_status_only_ablation_never_calls_failed_execution_safe(
    allowed, status, http_status, expected
):
    result = {"expected_allowed": allowed, "status": status, "http_status": http_status}
    assert status_only_prediction(result) == expected


def _matrix():
    cases = [
        ("cross-read", "evaluation", "read", "alice", "bob-private-2", False),
        ("cross-preview", "evaluation", "preview", "alice", "bob-private-2", False),
        ("guest-private", "evaluation", "read", "guest", "bob-private-2", False),
        ("admin-read", "evaluation", "admin-read", "admin", "users", True),
        ("own-read", "development", "read", "alice", "alice-private-1", True),
    ]
    return {
        "schema_version": 1, "corpus_id": "aegis-bac-v1", "description": "Test cases",
        "cases": [dict(zip(
            ("id", "split", "operation", "actor", "resource", "expected_allowed"), case
        )) for case in cases],
    }


def _stub_research(monkeypatch, *, transform=None, error=None):
    calls, exports = [], []

    def run_research(**kwargs):
        calls.append(copy.deepcopy(kwargs))
        if error:
            raise error
        results = []
        for case in kwargs["matrix"]["cases"]:
            if kwargs["split"] != "all" and case["split"] != kwargs["split"]:
                continue
            violation = expected_violation(kwargs["mode"], case)
            result = {
                **case, "status": "violation" if violation else "no_violation",
                "http_status": 200 if violation or case["expected_allowed"]
                or case["operation"] == "preview" else 403,
                "duration_seconds": 0.1, "reason": "observed result", "evidence": {},
            }
            results.append(transform(result, kwargs) if transform else result)
        return {
            "kind": "bac-research", "run_id": f"run-{len(calls)}", "results": results,
            "status": "blocked" if any(r["status"] == "violation" for r in results) else "allowed",
            "manifest_path": str(Path(kwargs["output_dir"]) / f"run-{len(calls)}" / "scan-manifest.json"),
        }

    def export_report(report, matrix, output_dir):
        exports.append((copy.deepcopy(report), copy.deepcopy(matrix), Path(output_dir)))
        return {**report, "output_dir": str(output_dir),
                "manifest_path": str(Path(output_dir) / "scan-manifest.json")}

    bac = types.ModuleType("app.bac")
    bac.run_research = run_research
    config = types.ModuleType("app.bac_config")
    config.validate_matrix = lambda matrix: copy.deepcopy(matrix)
    reports = types.ModuleType("app.bac_reports")
    reports.export_report = export_report
    monkeypatch.setitem(sys.modules, "app.bac", bac)
    monkeypatch.setitem(sys.modules, "app.bac_config", config)
    monkeypatch.setitem(sys.modules, "app.bac_reports", reports)
    return calls, exports


def test_benchmark_uses_paired_runs_and_shared_traces_without_mutating_input(tmp_path, monkeypatch):
    matrix = _matrix()
    original = copy.deepcopy(matrix)
    calls, exports = _stub_research(monkeypatch)

    report = run_benchmark(matrix=matrix, split="evaluation", repeats=2, output_dir=tmp_path)

    assert matrix == original
    assert [call["mode"] for call in calls] == ["fixed", "vulnerable", "fixed", "vulnerable"]
    assert all(call["split"] == "evaluation" for call in calls)
    assert report["kind"] == "bac-benchmark"
    assert report["exit_code"] == 0
    assert report["status"] == "allowed"
    assert len(report["results"]) == 16
    assert report["metrics"]["enhanced"]["overall"]["tp"] == 4
    assert report["metrics"]["enhanced"]["overall"]["tn"] == 12
    assert report["metrics"]["http-status-only"]["overall"]["fp"] == 2
    assert report["metrics"]["enhanced"]["by_operation"]["preview"]["fp"] == 0
    assert report["metrics"]["enhanced"]["by_split"]["evaluation"]["total"] == 16
    assert report["sample_counts"] == {
        "distinct_scenarios": 4, "distinct_mode_cases": 8, "attempted_observations": 16,
    }
    assert set(report["metrics"]["enhanced"]["by_repeat"]) == {"1", "2"}
    assert report["metrics"]["enhanced"]["by_repeat"]["1"]["total"] == 8
    assert report["metrics"]["http-status-only"]["by_repeat"]["2"]["fp"] == 1
    assert report["runtime"]["case_seconds"] == pytest.approx(1.6)
    assert len(report["runs"]) == 4
    assert len(exports) == 1
    assert exports[0][1] == matrix
    assert len(report["matrix_sha256"]) == 64
    assert report["metadata"]["baseline"] == "http-status-only"


def test_benchmark_misclassification_fails_without_fabricating_operational_error(tmp_path, monkeypatch):
    def miss_read(result, kwargs):
        if kwargs["mode"] == "vulnerable" and result["id"] == "cross-read":
            return {**result, "status": "no_violation"}
        return result

    _stub_research(monkeypatch, transform=miss_read)
    report = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)

    assert report["status"] == "blocked"
    assert report["exit_code"] == 1
    assert report["metrics"]["enhanced"]["overall"]["fn"] == 1
    assert report["operational_errors"] == []


def test_benchmark_inconclusive_case_fails_separately_from_false_negative(tmp_path, monkeypatch):
    def timeout(result, kwargs):
        if kwargs["mode"] == "vulnerable" and result["id"] == "cross-read":
            return {**result, "status": "inconclusive", "http_status": None,
                    "reason": "request timed out"}
        return result

    _stub_research(monkeypatch, transform=timeout)
    report = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)

    assert report["status"] == "error"
    assert report["exit_code"] == 2
    assert report["metrics"]["enhanced"]["overall"]["inconclusive"] == 1
    assert report["metrics"]["enhanced"]["overall"]["fn"] == 0
    assert len(report["operational_errors"]) == 1
    assert report["operational_errors"][0]["id"] == "cross-read"


def test_benchmark_missing_case_is_inconclusive_not_dropped(tmp_path, monkeypatch):
    calls, _ = _stub_research(monkeypatch)
    original = sys.modules["app.bac"].run_research

    def missing(**kwargs):
        report = original(**kwargs)
        return {**report, "results": report["results"][1:]}

    sys.modules["app.bac"].run_research = missing
    report = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)

    assert len(calls) == 2
    assert len(report["results"]) == 8
    assert report["exit_code"] == 2
    assert report["metrics"]["enhanced"]["overall"]["inconclusive"] == 2


@pytest.mark.parametrize("change", ["duplicate", "wrong-actor", "invalid-status", "unexpected"])
def test_benchmark_rejects_results_that_break_trial_identity(tmp_path, monkeypatch, change):
    _stub_research(monkeypatch)
    original = sys.modules["app.bac"].run_research

    def altered(**kwargs):
        report = original(**kwargs)
        first = report["results"][0]
        if change == "duplicate":
            report["results"].append(copy.deepcopy(first))
        elif change == "wrong-actor":
            report["results"][0] = {**first, "actor": "bob"}
        elif change == "invalid-status":
            report["results"][0] = {**first, "status": "safe"}
        else:
            report["results"].append({**first, "id": "not-in-matrix"})
        return report

    sys.modules["app.bac"].run_research = altered
    report = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)

    assert report["exit_code"] == 2
    assert len(report["results"]) == 8
    assert len(report["operational_errors"]) == 2


def test_benchmark_binds_subrun_manifest_digests(tmp_path, monkeypatch):
    import hashlib

    _stub_research(monkeypatch)
    original = sys.modules["app.bac"].run_research

    def exported(**kwargs):
        report = original(**kwargs)
        manifest = Path(report["manifest_path"])
        manifest.parent.mkdir(parents=True)
        manifest.write_text("synthetic signed manifest")
        return report

    sys.modules["app.bac"].run_research = exported
    report = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)

    digest = hashlib.sha256(b"synthetic signed manifest").hexdigest()
    assert all(run["manifest_sha256"] == digest for run in report["runs"])


def test_benchmark_runner_exception_does_not_erase_cases(tmp_path, monkeypatch):
    _stub_research(monkeypatch, error=RuntimeError("synthetic runner failure"))
    report = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)

    assert report["exit_code"] == 2
    assert len(report["results"]) == 8
    assert report["metrics"]["enhanced"]["overall"]["coverage"] == 0.0
    assert report["metrics"]["enhanced"]["overall"]["accuracy"] is None
    assert len(report["operational_errors"]) == 8


@pytest.mark.parametrize("repeats", [0, -1, True, 21, 1.5])
def test_benchmark_rejects_invalid_repetitions_before_writing(tmp_path, monkeypatch, repeats):
    calls, exports = _stub_research(monkeypatch)
    output = tmp_path / "not-created"

    with pytest.raises(ValueError, match="repeats"):
        run_benchmark(matrix=_matrix(), repeats=repeats, output_dir=output)

    assert not output.exists()
    assert calls == [] and exports == []


def test_benchmark_rejects_empty_or_invalid_split_before_writing(tmp_path, monkeypatch):
    _stub_research(monkeypatch)
    matrix = {**_matrix(), "cases": [_matrix()["cases"][-1]]}
    output = tmp_path / "not-created"

    for split in ("unknown", "evaluation"):
        with pytest.raises(ValueError, match="split"):
            run_benchmark(matrix=matrix, split=split, output_dir=output)
    assert not output.exists()


def test_benchmark_creates_unique_directory_and_preserves_existing_files(tmp_path, monkeypatch):
    _stub_research(monkeypatch)
    existing = tmp_path / "report.json"
    existing.write_text("user-owned")

    first = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)
    second = run_benchmark(matrix=_matrix(), repeats=1, output_dir=tmp_path)

    assert first["output_dir"] != second["output_dir"]
    assert Path(first["output_dir"]).parent.parent == tmp_path
    assert existing.read_text() == "user-owned"


def test_default_corpus_contains_independent_splits_and_both_permission_labels():
    import json

    matrix = json.loads((Path(__file__).resolve().parents[2] / "rules" / "bac-matrix-v2.json").read_text())
    cases = matrix["cases"]
    assert matrix["schema_version"] == 1
    assert len(cases) == 40
    assert len({case["id"] for case in cases}) == len(cases)
    for split, suffix in (("development", "-1"), ("evaluation", "-2")):
        selected = [case for case in cases if case["split"] == split]
        assert len(selected) == 20
        assert {case["expected_allowed"] for case in selected} == {True, False}
        assert {case["operation"] for case in selected} == {
            "read", "preview", "list", "export", "update", "rename", "delete", "admin-read", "admin-disable"
        }
        assert all(case["resource"].endswith(suffix) for case in selected
                   if "private" in case["resource"])


def _black_box_result(probe_status, probe_body, owner_body, *, resource="alice-private-2", owner_status=200):
    return {
        "status": "no_violation", "expected_allowed": False, "actor": "bob", "resource": resource,
        "evidence": {"probe": {"status_code": probe_status, "body": probe_body},
                     "baseline": {"status_code": owner_status, "body": owner_body}},
    }


OWNER_VIEW = {"id": "alice-private-2", "title": "Alice private-2 document", "content": "synthetic-canary:alice-private-2"}


@pytest.mark.parametrize("probe_status, probe_body, differential, leak", [
    (200, OWNER_VIEW, "violation", "violation"),
    (200, {"id": "alice-private-2", "title": "Alice private-2 document"}, "no_violation", "violation"),
    (403, {"detail": "denied", "document": OWNER_VIEW}, "no_violation", "violation"),
    (403, {"detail": "Document ownership is required"}, "no_violation", "no_violation"),
])
def test_black_box_methods_use_only_owner_and_attacker_responses(probe_status, probe_body, differential, leak):
    from app.bac_benchmark import content_leak_prediction, differential_prediction

    result = _black_box_result(probe_status, probe_body, OWNER_VIEW)
    assert differential_prediction(result) == differential
    assert content_leak_prediction(result) == leak


def test_content_leak_compares_the_targeted_record_inside_collections():
    from app.bac_benchmark import content_leak_prediction

    shared = {"id": "alice-public", "title": "Alice public document", "content": "synthetic-canary:alice-public"}
    owner = {"documents": [OWNER_VIEW, shared]}
    assert content_leak_prediction(_black_box_result(200, {"documents": [shared]}, owner)) == "no_violation"
    assert content_leak_prediction(_black_box_result(200, {"documents": [shared, OWNER_VIEW]}, owner)) == "violation"


def test_black_box_methods_skip_allowed_controls_and_missing_evidence():
    from app.bac_benchmark import content_leak_prediction, differential_prediction

    allowed = {"status": "no_violation", "expected_allowed": True, "evidence": {}}
    incomplete = {**_black_box_result(403, {}, OWNER_VIEW), "status": "inconclusive"}
    for method in (differential_prediction, content_leak_prediction):
        assert method(allowed) == "no_violation"
        assert method(incomplete) == "inconclusive"
        assert method({**incomplete, "status": "no_violation", "evidence": {}}) == "inconclusive"


def test_live_corpus_separates_black_box_failure_modes(tmp_path):
    from app.bac_config import load_matrix

    report = run_benchmark(matrix=load_matrix(), split="evaluation", repeats=1, output_dir=tmp_path)
    vulnerable = {row["operation"]: row for row in report["results"]
                  if row["mode"] == "vulnerable" and row["expected_violation"]}
    assert all(row["prediction"] == "violation" for row in vulnerable.values())
    assert vulnerable["export"]["http_status"] == vulnerable["rename"]["http_status"] == 403
    assert vulnerable["export"]["baseline_prediction"] == vulnerable["rename"]["baseline_prediction"] == "no_violation"
    assert vulnerable["export"]["content_leak_prediction"] == "violation"
    assert vulnerable["rename"]["content_leak_prediction"] == vulnerable["rename"]["differential_prediction"] == "no_violation"
    fixed_list = next(row for row in report["results"] if row["mode"] == "fixed" and row["id"] == "eval-alice-cross-list")
    assert fixed_list["baseline_prediction"] == "violation" and fixed_list["differential_prediction"] == "no_violation"
    assert set(report["metrics"]) == {"enhanced", "http-status-only", "differential", "content-leak"}
