#!/usr/bin/env python3
"""Run a held-out source/sink corpus, or pinned real repositories, through CodeQL and Semgrep."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from app.codeql_scanner import _detected_languages, run_codeql_scan_isolated
from app.scan_engine import add_semgrep_excludes


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS = PROJECT_ROOT / "benchmarks" / "codeql-heldout-v1.json"
REPOSITORIES = PROJECT_ROOT / "benchmarks" / "repositories-v1.json"
SEMGREP_RULES = PROJECT_ROOT / "rules" / "semgrep_rules.yaml"
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


def _load_cases(corpus_path: Path) -> tuple[bytes, list[dict]]:
    content = corpus_path.read_bytes()
    corpus = json.loads(content)
    cases = corpus.get("cases")
    if corpus.get("schema_version") != 1 or not isinstance(cases, list) or not cases:
        raise ValueError("CodeQL corpus must contain schema v1 cases.")
    ids = [case.get("id") for case in cases]
    files = [case.get("file") for case in cases]
    if any(not isinstance(value, str) or not value for value in ids + files) or len(set(ids)) != len(ids) or len(set(files)) != len(files):
        raise ValueError("CodeQL case IDs and paths must be unique nonempty strings.")
    return content, cases


def _write_sources(cases: list[dict], source: Path) -> None:
    for case in cases:
        relative = Path(case["file"])
        if relative.is_absolute() or ".." in relative.parts or relative.suffix not in {".py", ".js"}:
            raise ValueError("CodeQL case paths must be relative Python or JavaScript files.")
        if not isinstance(case.get("source"), str):
            raise ValueError("CodeQL case source must be text.")
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(case["source"], encoding="utf-8")


def _isolated_codeql(source: Path, output: Path) -> tuple[dict[str, set[str]], dict]:
    docker_executable = shutil.which("docker")
    if not docker_executable:
        raise RuntimeError("The CodeQL benchmark requires the Docker CLI (or pass --codeql-cli).")
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
    report = run_codeql_scan_isolated(
        source, output, image=_image(), query_suites=SUITES, docker_host=docker_host,
    )
    findings: dict[str, set[str]] = {}
    for finding in report["findings"]:
        findings.setdefault(finding["filename"], set()).add(finding["rule_id"])
    return findings, {
        "runtime": "isolated-container",
        "image": report["tool"]["image"],
        "codeql_version": report["tool"]["version"],
        "query_suites": report["query_suites"],
        "languages": report["coverage"]["languages"],
        "isolation": report["coverage"]["isolation"],
        "sarif_sha256": hashlib.sha256((output / "codeql.sarif").read_bytes()).hexdigest(),
    }


def _direct_codeql(codeql: Path, source: Path, output: Path) -> tuple[dict[str, set[str]], dict]:
    """Run a local CodeQL CLI with the same pinned suites, without the container.

    The benchmark sources are the fixed corpus, not untrusted repositories, so
    isolation does not change what is measured: which queries fire.
    """
    version = subprocess.run(
        [str(codeql), "version", "--format=terse"], capture_output=True, text=True, timeout=120, check=True,
    ).stdout.strip()
    findings: dict[str, set[str]] = {}
    digests = {}
    languages = _detected_languages(source)
    for language in languages:
        suite = SUITES[language]
        database = output / f"db-{language}"
        sarif = output / f"{language}.sarif"
        subprocess.run(
            [str(codeql), "database", "create", str(database), f"--language={language}",
             f"--source-root={source}", "--build-mode=none", "--overwrite", "--quiet"],
            check=True, timeout=600, stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [str(codeql), "database", "analyze", str(database), suite,
             "--format=sarif-latest", f"--output={sarif}", "--quiet"],
            check=True, timeout=1200, stdout=subprocess.DEVNULL,
        )
        digests[language] = hashlib.sha256(sarif.read_bytes()).hexdigest()
        for run in json.loads(sarif.read_text(encoding="utf-8"))["runs"]:
            for result in run.get("results", []):
                uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                findings.setdefault(uri, set()).add(result["ruleId"])
    return findings, {
        "runtime": "direct-cli",
        "codeql_version": version,
        "query_suites": SUITES,
        "languages": languages,
        "isolation": "not-applicable (benchmark sources, not untrusted uploads)",
        "sarif_sha256": digests,
    }


def _package_version(name: str) -> str:
    # `semgrep --version` performs a network version check; read metadata instead.
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _semgrep(source: Path, *, allow_errors: bool = False) -> tuple[dict[str, set[str]], dict]:
    semgrep = shutil.which("semgrep")
    if not semgrep:
        raise RuntimeError("semgrep is not installed.")
    # Same target selection as production scans, so repository runs match what Aegis reports.
    command = add_semgrep_excludes([semgrep, "scan", "--metrics", "off", "--disable-version-check",
                                    "--config", str(SEMGREP_RULES), "--json", "--quiet"])
    completed = subprocess.run(
        [*command, str(source)], capture_output=True, text=True, timeout=1800, check=False,
    )
    report = json.loads(completed.stdout)
    if report.get("errors") and not allow_errors:
        raise RuntimeError(f"Semgrep reported errors: {report['errors']}")
    findings: dict[str, set[str]] = {}
    for item in report["results"]:
        relative = Path(item["path"]).resolve().relative_to(source.resolve()).as_posix()
        findings.setdefault(relative, set()).add(str(item["check_id"]).rsplit(".", 1)[-1])
    return findings, {
        "rules_sha256": hashlib.sha256(SEMGREP_RULES.read_bytes()).hexdigest(),
        "version": _package_version("semgrep"),
        "errors": len(report.get("errors") or []),
    }


def _score(cases: list[dict], detected) -> dict:
    tp = fn = fp = tn = 0
    for case in cases:
        hit = detected(case)
        if case["expected_rule_id"]:
            tp += hit
            fn += not hit
        else:
            fp += hit
            tn += not hit
    return {
        "true_positives": tp, "false_negatives": fn, "false_positives": fp, "true_negatives": tn,
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


def run_benchmark(
    corpus_path: Path = CORPUS,
    *,
    codeql_cli: Path | None = None,
    with_semgrep: bool = False,
) -> dict:
    content, cases = _load_cases(corpus_path)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="aegis-codeql-benchmark-") as temporary:
        root = Path(temporary)
        source = root / "source"
        output = root / "output"
        output.mkdir()
        _write_sources(cases, source)
        if codeql_cli:
            codeql_findings, codeql_tool = _direct_codeql(codeql_cli, source, output)
        else:
            codeql_findings, codeql_tool = _isolated_codeql(source, output)
        semgrep_findings, semgrep_tool = _semgrep(source) if with_semgrep else ({}, None)

    target_rules = {case["expected_rule_id"] for case in cases if case["expected_rule_id"]}
    results = []
    for case in cases:
        actual_rules = sorted(codeql_findings.get(case["file"], set()))
        expected = case.get("expected_rule_id")
        results.append({
            "id": case["id"],
            "expected_rule_id": expected,
            "actual_rule_ids": actual_rules,
            "semgrep_rule_ids": sorted(semgrep_findings.get(case["file"], set())) if with_semgrep else None,
            "passed": expected in actual_rules if expected else not actual_rules,
        })
    by_id = {result["id"]: result for result in results}

    def codeql_hit(case):
        actual = by_id[case["id"]]["actual_rule_ids"]
        return case["expected_rule_id"] in actual if case["expected_rule_id"] else bool(actual)

    def codeql_target_hit(case):
        # Count only the vulnerability classes this corpus targets; ignore
        # unrelated queries such as missing rate limiting.
        actual = set(by_id[case["id"]]["actual_rule_ids"]) & target_rules
        return case["expected_rule_id"] in actual if case["expected_rule_id"] else bool(actual)

    def semgrep_hit(case):
        return bool(by_id[case["id"]]["semgrep_rule_ids"])

    metrics = {"cases": len(cases), **_score(cases, codeql_hit)}
    report = {
        "schema_version": 2,
        "status": "completed",
        "passed": all(result["passed"] for result in results),
        "corpus": corpus_path.name,
        "corpus_sha256": hashlib.sha256(content).hexdigest(),
        "source_scope": "synthetic-held-out-fixtures",
        **codeql_tool,
        "metrics": metrics,
        "codeql_target_class_metrics": _score(cases, codeql_target_hit),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "results": results,
    }
    if with_semgrep:
        report["semgrep"] = {
            **(semgrep_tool or {}),
            "metrics": _score(cases, semgrep_hit),
            "combined_with_codeql": _score(cases, lambda case: codeql_hit(case) or semgrep_hit(case)),
        }
    return report


def _inventory(findings: dict[str, set[str]]) -> dict:
    """List flagged (file, rule) pairs: the unit a reviewer triages."""
    by_rule: dict[str, list[str]] = {}
    for path, rules in sorted(findings.items()):
        for rule in rules:
            by_rule.setdefault(rule, []).append(path)
    return {
        "flagged_files": len(findings),
        "file_rule_pairs": sum(len(paths) for paths in by_rule.values()),
        "by_rule": dict(sorted(by_rule.items())),
    }


def _checkout(url: str, commit: str, destination: Path) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Repository commits must be full 40-character SHAs.")
    destination.mkdir()
    for arguments in (["init", "-q"], ["fetch", "-q", "--depth", "1", url, commit], ["checkout", "-q", "FETCH_HEAD"]):
        subprocess.run(["git", "-C", str(destination), *arguments], check=True, timeout=600)


def run_repositories(manifest_path: Path = REPOSITORIES, *, codeql_cli: Path | None = None) -> dict:
    manifest_bytes = manifest_path.read_bytes()
    repositories = json.loads(manifest_bytes)["repositories"]
    results = []
    for repository in repositories:
        started = time.monotonic()
        entry = {key: repository[key] for key in ("name", "url", "commit", "kind", "stack")}
        try:
            with tempfile.TemporaryDirectory(prefix="aegis-repository-benchmark-") as temporary:
                source, output = Path(temporary) / "source", Path(temporary) / "output"
                output.mkdir()
                _checkout(repository["url"], repository["commit"], source)
                if codeql_cli:
                    codeql_findings, codeql_tool = _direct_codeql(codeql_cli, source, output)
                else:
                    codeql_findings, codeql_tool = _isolated_codeql(source, output)
                semgrep_findings, semgrep_tool = _semgrep(source, allow_errors=True)
            entry.update({
                "status": "completed",
                "languages": codeql_tool["languages"],
                "codeql": _inventory(codeql_findings),
                "semgrep": {**_inventory(semgrep_findings), "errors": semgrep_tool["errors"]},
            })
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            entry.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        entry["elapsed_seconds"] = round(time.monotonic() - started, 3)
        results.append(entry)
    failures = sum(result["status"] == "failed" for result in results)
    return {
        "schema_version": 1,
        "status": "completed",
        "passed": failures == 0,
        "source_scope": "pinned-public-repositories-untriaged",
        "manifest": manifest_path.name,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "codeql_runtime": "direct-cli" if codeql_cli else "isolated-container",
        "semgrep_rules_sha256": hashlib.sha256(SEMGREP_RULES.read_bytes()).hexdigest(),
        "semgrep_version": _package_version("semgrep"),
        "operational_failures": failures,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--codeql-cli", type=Path, help="Run a local CodeQL CLI instead of the isolated container")
    parser.add_argument("--with-semgrep", action="store_true", help="Also score the Aegis Semgrep rules")
    parser.add_argument("--repositories", type=Path, nargs="?", const=REPOSITORIES,
                        help="Inventory alerts on pinned real repositories instead of scoring the corpus")
    arguments = parser.parse_args()
    if arguments.repositories:
        report = run_repositories(arguments.repositories, codeql_cli=arguments.codeql_cli)
    else:
        report = run_benchmark(arguments.corpus, codeql_cli=arguments.codeql_cli, with_semgrep=arguments.with_semgrep)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
