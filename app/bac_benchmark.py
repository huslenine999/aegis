"""Paired, labeled evaluation of the owned broken-access-control lab."""

from __future__ import annotations

import hashlib
import platform
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .evidence import canonical_json
from .safe_output import SafeOutputRoot
from .version import get_package_version


PREDICTIONS = {"violation", "no_violation", "inconclusive"}
BASELINE = "http-status-only"


def classification_metrics(rows: list[dict]) -> dict:
    """Score completed classifications; report execution failures separately."""
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "inconclusive": 0}
    for row in rows:
        expected = row.get("expected_violation")
        prediction = row.get("prediction")
        if type(expected) is not bool or not isinstance(prediction, str) or prediction not in PREDICTIONS:
            raise ValueError("Metrics require boolean labels and valid predictions.")
        if prediction == "inconclusive":
            counts["inconclusive"] += 1
        else:
            positive = prediction == "violation"
            key = ("tp" if expected else "fp") if positive else ("fn" if expected else "tn")
            counts[key] += 1
    scored = len(rows) - counts["inconclusive"]

    def ratio(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "total": len(rows), "scored": scored, **counts,
        "coverage": ratio(scored, len(rows)),
        "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
        "false_positive_rate": ratio(counts["fp"], counts["fp"] + counts["tn"]),
        "accuracy": ratio(counts["tp"] + counts["tn"], scored),
    }


def expected_violation(mode: str, case: dict) -> bool:
    """Ground truth for seeded lab bugs; never pass this label to the detector."""
    return mode == "vulnerable" and not case["expected_allowed"] and case["actor"] != "guest"


def status_only_prediction(result: dict) -> str:
    """Ablate body/state checks on the same trace, not an independent baseline."""
    status = result.get("http_status")
    if result.get("status") == "inconclusive" or type(status) is not int:
        return "inconclusive"
    return "violation" if not result["expected_allowed"] and 200 <= status < 300 else "no_violation"


def _metric_groups(rows: list[dict], prediction_key: str) -> dict:
    scored_rows = [{**row, "prediction": row[prediction_key]} for row in rows]
    grouped = {"overall": classification_metrics(scored_rows)}
    for field in ("mode", "operation", "split", "repeat"):
        grouped[f"by_{field}"] = {
            str(value): classification_metrics([row for row in scored_rows if row[field] == value])
            for value in sorted({row[field] for row in scored_rows})
        }
    return grouped


def benchmark_measurements(rows: list[dict]) -> dict:
    """Keep repeated observations separate from distinct seeded scenarios."""
    return {
        "metrics": {"enhanced": _metric_groups(rows, "prediction"),
                    BASELINE: _metric_groups(rows, "baseline_prediction")},
        "sample_counts": {
            "distinct_scenarios": len({row["id"] for row in rows}),
            "distinct_mode_cases": len({(row["mode"], row["id"]) for row in rows}),
            "attempted_observations": len(rows),
        },
    }


def _inconclusive(case: dict, reason: str) -> dict:
    return {**case, "status": "inconclusive", "http_status": None,
            "duration_seconds": 0.0, "reason": reason, "evidence": {}}


def _paired_rows(report: dict, cases: list[dict], mode: str, repeat: int) -> list[dict]:
    results = report.get("results", [])
    results = results if isinstance(results, list) else []
    rows = []
    for case in cases:
        matching = [result for result in results
                    if isinstance(result, dict) and result.get("id") == case["id"]]
        if len(matching) != 1:
            reason = "Missing case result." if not matching else "Duplicate case results."
            result = _inconclusive(case, reason)
        else:
            result = matching[0]
            if result.get("status") not in PREDICTIONS:
                result = _inconclusive(case, "Invalid case classification.")
            elif any(result.get(field) != case[field] for field in case):
                result = _inconclusive(case, "Case result does not match the labeled matrix.")
        rows.append({
            **result, **case, "mode": mode, "repeat": repeat, "trial_run_id": report.get("run_id"),
            "expected_violation": expected_violation(mode, case),
            "prediction": result["status"],
            "baseline_prediction": status_only_prediction(result),
        })
    return rows


def run_benchmark(
    *, matrix: dict, split: str = "evaluation", repeats: int = 3,
    output_dir: str | Path, protocol: str | Path | None = None,
) -> dict:
    """Run paired fixed/vulnerable trials and export a signed evaluation summary."""
    from .bac import run_research
    from .bac_config import validate_matrix
    from .bac_reports import export_report

    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError("repeats must be an integer from 1 to 20.")
    if split not in {"all", "development", "evaluation"}:
        raise ValueError("split must be all, development, or evaluation.")
    matrix = validate_matrix(matrix)
    cases = [case for case in matrix["cases"] if split == "all" or case["split"] == split]
    if not cases:
        raise ValueError("The requested split contains no cases.")
    study = None
    if protocol is not None:
        from .bac_config import validate_study_protocol

        study = validate_study_protocol(protocol, matrix=matrix, split=split, repeats=repeats)

    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()
    run_id = "bac-benchmark-" + uuid.uuid4().hex
    experiment_dir = SafeOutputRoot(output_dir).directory(run_id)
    rows: list[dict] = []
    runs: list[dict] = []
    errors: list[dict] = []
    for repeat in range(1, repeats + 1):
        for mode in ("fixed", "vulnerable"):
            trial_dir = experiment_dir / f"{repeat:03d}-{mode}"
            trial_started = time.perf_counter()
            try:
                report = run_research(mode=mode, matrix=matrix, split=split, output_dir=trial_dir)
            except Exception as exc:
                reason = f"Research run failed ({type(exc).__name__})."
                report = {"status": "error", "results": [_inconclusive(case, reason) for case in cases]}
            paired = _paired_rows(report, cases, mode, repeat)
            rows.extend(paired)
            errors.extend({"id": row["id"], "mode": mode, "repeat": repeat,
                           "reason": row.get("reason", "Case did not complete.")}
                          for row in paired if row["prediction"] == "inconclusive")
            expected_ids = {case["id"] for case in cases}
            unexpected = [result.get("id") for result in report.get("results", [])
                          if isinstance(result, dict) and result.get("id") not in expected_ids]
            if unexpected or (report.get("status") == "error" and not any(
                row["prediction"] == "inconclusive" for row in paired
            )):
                errors.append({"id": None, "mode": mode, "repeat": repeat,
                               "reason": "Research run has an operational error or unexpected case results."})
            manifest_path = report.get("manifest_path")
            manifest_hash = None
            if manifest_path and Path(manifest_path).is_file():
                manifest_hash = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()
            runs.append({
                "mode": mode, "repeat": repeat, "run_id": report.get("run_id"),
                "status": report.get("status"), "duration_seconds": time.perf_counter() - trial_started,
                "manifest_path": manifest_path, "manifest_sha256": manifest_hash,
                "versions": report.get("versions"),
            })

    measurements = benchmark_measurements(rows)
    overall = measurements["metrics"]["enhanced"]["overall"]
    status = "error" if errors else "blocked" if overall["fp"] or overall["fn"] else "allowed"
    summary = {
        "schema_version": 1, "kind": "bac-benchmark", "run_id": run_id,
        "corpus_id": matrix["corpus_id"], "matrix_sha256": hashlib.sha256(canonical_json(matrix)).hexdigest(),
        "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(),
        "split": split, "repeats": repeats, "experiment_dir": str(experiment_dir),
        "results": rows, "runs": runs, **measurements, "operational_errors": errors,
        "status": status, "exit_code": {"allowed": 0, "blocked": 1, "error": 2}[status],
        "runtime": {"wall_seconds": time.perf_counter() - started,
                    "case_seconds": sum(row.get("duration_seconds", 0.0) for row in rows)},
        "metadata": {
            "aegis_version": get_package_version(), "python_version": platform.python_version(),
            "benchmark_version": 1, "baseline": BASELINE,
            "baseline_kind": "same-trace ablation", "ground_truth": "seeded owned lab permissions",
            "scope": "One synthetic lab corpus; evaluation split is not external unseen validation.",
        },
        **({"study_protocol": {"definition": study,
                               "canonical_sha256": hashlib.sha256(canonical_json(study)).hexdigest()}}
           if study is not None else {}),
        "findings": [],
    }
    return export_report(summary, matrix, experiment_dir / "summary")
