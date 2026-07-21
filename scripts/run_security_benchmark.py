#!/usr/bin/env python3
"""Run the versioned release corpus against the shipped Aegis scanner."""

import argparse
import contextlib
import hashlib
import io
import json
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from app.cli import execute_scan


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = PROJECT_ROOT / "benchmarks" / "corpus-v1.json"


def _load_corpus(path: Path) -> tuple[dict, str]:
    content = path.read_bytes()
    corpus = json.loads(content)
    cases = corpus.get("cases")
    if corpus.get("schema_version") != 1 or not isinstance(cases, list) or len(cases) < 10:
        raise ValueError("Benchmark corpus must be schema v1 with at least ten cases.")
    names = [str(case.get("name", "")) for case in cases]
    if not all(names) or len(names) != len(set(names)):
        raise ValueError("Benchmark case names must be present and unique.")
    return corpus, hashlib.sha256(content).hexdigest()


def run_benchmark(corpus_path: Path = DEFAULT_CORPUS) -> dict:
    corpus, corpus_sha256 = _load_corpus(corpus_path)
    results = []
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="aegis-benchmark-") as temporary:
        root = Path(temporary)
        for case in corpus["cases"]:
            target = root / f"{case['name']}.py"
            output = root / f"{case['name']}-reports"
            target.write_text(str(case["source"]))
            captured = io.StringIO()
            case_started = time.perf_counter()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                summary = execute_scan(
                    str(target),
                    use_docker=False,
                    fast=True,
                    strict=False,
                    quiet=True,
                    output_dir=str(output),
                    return_summary=True,
                )
            expected = "blocked" if case["vulnerable"] else "allowed"
            results.append(
                {
                    "name": case["name"],
                    "category": case["category"],
                    "expected": expected,
                    "actual": summary["status"],
                    "passed": summary["status"] == expected,
                    "duration_seconds": round(time.perf_counter() - case_started, 3),
                }
            )

    positives = [item for item in results if item["expected"] == "blocked"]
    negatives = [item for item in results if item["expected"] == "allowed"]
    true_positives = sum(item["actual"] == "blocked" for item in positives)
    false_negatives = len(positives) - true_positives
    true_negatives = sum(item["actual"] == "allowed" for item in negatives)
    false_positives = len(negatives) - true_negatives
    category_totals: dict[str, list[bool]] = defaultdict(list)
    for item in results:
        category_totals[item["category"]].append(item["passed"])
    precision_denominator = true_positives + false_positives
    metrics = {
        "recall": true_positives / len(positives),
        "precision": true_positives / precision_denominator if precision_denominator else 1.0,
        "false_positive_rate": false_positives / len(negatives),
        "accuracy": (true_positives + true_negatives) / len(results),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "cases": len(results),
        "duration_seconds": round(time.perf_counter() - started, 3),
    }
    return {
        "schema_version": 2,
        "corpus": str(corpus_path),
        "corpus_sha256": corpus_sha256,
        "passed": all(item["passed"] for item in results),
        "metrics": metrics,
        "categories": {
            category: {
                "cases": len(values),
                "passed": sum(values),
                "pass_rate": sum(values) / len(values),
            }
            for category, values in sorted(category_totals.items())
        },
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--min-recall", type=float, default=1.0)
    parser.add_argument("--max-false-positive-rate", type=float, default=0.0)
    arguments = parser.parse_args()
    report = run_benchmark(arguments.corpus)
    report["thresholds"] = {
        "min_recall": arguments.min_recall,
        "max_false_positive_rate": arguments.max_false_positive_rate,
    }
    report["passed"] = bool(
        report["passed"]
        and report["metrics"]["recall"] >= arguments.min_recall
        and report["metrics"]["false_positive_rate"]
        <= arguments.max_false_positive_rate
    )
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(encoded)
    print(encoded, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
