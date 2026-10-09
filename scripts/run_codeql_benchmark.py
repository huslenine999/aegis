#!/usr/bin/env python3
"""Run the small held-out source/sink corpus in the isolated CodeQL runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from app.codeql_scanner import run_codeql_scan_isolated


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS = PROJECT_ROOT / "benchmarks" / "codeql-heldout-v1.json"
SUITES = {
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript-typescript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
}


def _image() -> str:
    image = os.environ.get("AEGIS_CODEQL_IMAGE", "").strip()
    if not image:
        for line in (PROJECT_ROOT / ".env.aegis").read_text(encoding="utf-8").splitlines():
            if line.startswith("AEGIS_CODEQL_IMAGE="):
                image = line.partition("=")[2].strip().strip("\"'")
                break
    if not re.fullmatch(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("Provision a CodeQL image pinned by SHA-256 digest.")
    return image


def run_benchmark(corpus_path: Path = CORPUS) -> dict:
    content = corpus_path.read_bytes()
    corpus = json.loads(content)
    cases = corpus.get("cases")
    if corpus.get("schema_version") != 1 or not isinstance(cases, list) or not cases:
        raise ValueError("CodeQL corpus must contain schema v1 cases.")
    ids = [case.get("id") for case in cases]
    files = [case.get("file") for case in cases]
    if any(not isinstance(value, str) or not value for value in ids + files) or len(set(ids)) != len(ids) or len(set(files)) != len(files):
        raise ValueError("CodeQL case IDs and paths must be unique nonempty strings.")

    docker_executable = shutil.which("docker")
    if not docker_executable:
        raise RuntimeError("The CodeQL benchmark requires the Docker CLI.")
    host_result = subprocess.run(
        [docker_executable, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    docker_host = host_result.stdout.strip()
    if not docker_host.startswith("unix://"):
        raise ValueError("The CodeQL benchmark requires a local Docker Unix socket.")

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="aegis-codeql-benchmark-") as temporary:
        root = Path(temporary)
        source = root / "source"
        output = root / "output"
        findings_by_file: dict[str, list[str]] = {}
        for case in cases:
            relative = Path(case["file"])
            if relative.is_absolute() or ".." in relative.parts or relative.suffix not in {".py", ".js"}:
                raise ValueError("CodeQL case paths must be relative Python or JavaScript files.")
            if not isinstance(case.get("source"), str):
                raise ValueError("CodeQL case source must be text.")
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(case["source"], encoding="utf-8")

        report = run_codeql_scan_isolated(
            source,
            output,
            image=_image(),
            query_suites=SUITES,
            docker_host=docker_host,
        )
        for finding in report["findings"]:
            findings_by_file.setdefault(finding["filename"], []).append(finding["rule_id"])
        results = []
        for case in cases:
            actual_rules = sorted(set(findings_by_file.get(case["file"], [])))
            expected = case.get("expected_rule_id")
            passed = expected in actual_rules if expected else not actual_rules
            results.append({
                "id": case["id"],
                "expected_rule_id": expected,
                "actual_rule_ids": actual_rules,
                "passed": passed,
            })
        positives = [case for case in cases if case["expected_rule_id"]]
        negatives = [case for case in cases if not case["expected_rule_id"]]
        true_positives = sum(result["passed"] for result in results if result["expected_rule_id"])
        false_positives = sum(bool(result["actual_rule_ids"]) for result in results if not result["expected_rule_id"])
        metrics = {
            "cases": len(cases),
            "true_positives": true_positives,
            "false_negatives": len(positives) - true_positives,
            "true_negatives": len(negatives) - false_positives,
            "false_positives": false_positives,
            "recall": true_positives / len(positives),
            "precision": true_positives / (true_positives + false_positives) if true_positives + false_positives else 1.0,
            "false_positive_rate": false_positives / len(negatives),
        }
        return {
            "schema_version": 1,
            "status": "completed",
            "passed": all(result["passed"] for result in results),
            "corpus": corpus_path.name,
            "corpus_sha256": hashlib.sha256(content).hexdigest(),
            "source_scope": "synthetic-held-out-fixtures",
            "image": report["tool"]["image"],
            "codeql_version": report["tool"]["version"],
            "query_suites": report["query_suites"],
            "languages": report["coverage"]["languages"],
            "isolation": report["coverage"]["isolation"],
            "sarif_sha256": hashlib.sha256((output / "codeql.sarif").read_bytes()).hexdigest(),
            "metrics": metrics,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "results": results,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    report = run_benchmark(arguments.corpus)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
