"""Redacted, signed artifacts for local BAC experiments, not source attestation."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .bac_benchmark import benchmark_measurements
from .evidence import canonical_json, sign_manifest
from .safe_output import SafeOutputError, SafeOutputRoot
from .version import get_package_version


_SECRET_FIELDS = frozenset({
    "authorization", "proxyauthorization", "cookie", "setcookie", "password",
    "passwd", "token", "accesstoken", "refreshtoken", "apikey", "secret",
    "clientsecret", "controltoken", "xaegislabkey", "tokens",
})
_METRIC_COLUMNS = (
    ("total", "Attempted"), ("scored", "Scored"), ("inconclusive", "Inconclusive"),
    ("tp", "TP"), ("fp", "FP"), ("tn", "TN"), ("fn", "FN"),
    ("coverage", "Coverage"), ("precision", "Precision"), ("recall", "Recall"),
    ("false_positive_rate", "False-positive rate"), ("accuracy", "Accuracy"),
)
_COMPARISON_COLUMNS = (("method", "Method"), ("group", "Group"), ("group_value", "Value")) + _METRIC_COLUMNS
_RATE_FIELDS = frozenset({"coverage", "precision", "recall", "false_positive_rate", "accuracy"})
_BENCHMARK_CASE_COLUMNS = (
    ("id", "Case"), ("mode", "Mode"), ("repeat", "Repeat"), ("trial_run_id", "Trial run"),
    ("actor", "Actor"), ("operation", "Operation"), ("resource", "Resource"),
    ("expected_violation", "Seeded violation"), ("prediction", "Enhanced"),
    ("baseline_prediction", "HTTP-status-only"), ("http_status", "HTTP status"), ("reason", "Reason"),
)
_BENCHMARK_SCOPE = (
    "HTTP-status-only is a same-trace ablation, not an independent scanner. "
    "One synthetic lab corpus; repeats are not independent samples or evidence of real-world accuracy. "
    "Undefined rates have no denominator; accuracy excludes inconclusive attempts, so report coverage alongside it."
)


def redact(value: Any, sensitive_values: tuple[str, ...] = ()) -> Any:
    """Remove credential fields and actual ephemeral token values recursively."""
    if isinstance(value, dict):
        return {
            redact(str(key), sensitive_values): "[REDACTED]" if _secret_field(str(key)) else redact(item, sensitive_values)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, sensitive_values) for item in value]
    if isinstance(value, str):
        result = value
        for secret in sensitive_values:
            if secret:
                result = result.replace(secret, "[REDACTED]")
        return result
    return value


def _secret_field(key: str) -> bool:
    normalized = "".join(character for character in key.lower() if character.isalnum())
    return normalized in _SECRET_FIELDS or normalized.endswith(("password", "token", "secret", "apikey"))


def validate_output_directory(output_dir: str | Path) -> Path:
    path = Path(output_dir).expanduser().absolute()
    if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
        raise ValueError("BAC output must be a new or empty non-symlink directory; existing files are preserved.")
    return path


def freeze_protocol(*, matrix: dict, split: str = "evaluation", repeats: int = 3, output_dir: str | Path) -> dict:
    from .bac_config import study_definition

    definition = study_definition(matrix=matrix, split=split, repeats=repeats)
    protocol = sign_manifest({
        **definition, "protocol_id": "bac-study-" + uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    destination = validate_output_directory(output_dir)
    try:
        output = SafeOutputRoot(destination)
        path = output.write_bounded_json("study-protocol.json", protocol)
    except SafeOutputError as exc:
        raise ValueError("BAC protocol output directory is unsafe.") from exc
    return {"status": "allowed", "exit_code": 0, "protocol": protocol,
            "output_dir": str(output.root), "manifest_path": str(path)}


def export_report(report: dict, matrix: dict, output_dir: str | Path) -> dict:
    destination = validate_output_directory(output_dir)
    try:
        output = SafeOutputRoot(destination)
    except SafeOutputError as exc:
        raise ValueError("BAC output directory is unsafe.") from exc
    measurements = benchmark_measurements(report.get("results", [])) if report.get("kind") == "bac-benchmark" else {}
    clean = redact({**report, **measurements,
                    "output_dir": str(output.root), "manifest_path": str(output.root / "scan-manifest.json")})
    results = clean.get("results", [])
    evidence = [{
        "id": item.get("id"), "run_id": item.get("trial_run_id", clean.get("run_id")),
        "mode": item.get("mode", clean.get("mode")), "repeat": item.get("repeat"),
        "actor": item.get("actor"), "operation": item.get("operation"), "resource": item.get("resource"),
        "evidence": item.get("evidence", {}),
    } for item in results]
    artifacts = {
        "report.json": clean,
        "matrix.json": redact(matrix),
        "findings.json": clean.get("findings", []),
        "evidence.json": evidence,
        "server-events.json": [{**event, **{key: item[key] for key in ("run_id", "mode", "repeat")}}
                               for item in evidence for event in item["evidence"].get("server_events", [])],
    }
    for name, payload in artifacts.items():
        output.write_bounded_json(name, payload)
    text_artifacts = {"report.md": _markdown(clean), "report.html": _html(clean),
                      **(_benchmark_csvs(clean) if clean.get("kind") == "bac-benchmark" else {})}
    for name, content_text in text_artifacts.items():
        output.write_text(name, content_text)
    inventory = []
    for name in (*artifacts, *text_artifacts):
        content = output.file(name).read_bytes()
        inventory.append({"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    manifest = sign_manifest({
        "schema_version": 2,
        "evidence_type": "bac-runtime-lab",
        "aegis_version": get_package_version(),
        "run_id": clean.get("run_id"),
        "status": clean.get("status", "error"),
        "exit_code": clean.get("exit_code", 2),
        "matrix_sha256": hashlib.sha256(canonical_json(matrix)).hexdigest(),
        "started_at": clean.get("started_at"),
        "completed_at": clean.get("completed_at"),
        "source_attestation": "not-claimed",
        "artifacts": inventory,
    })
    output.write_bounded_json("scan-manifest.json", manifest)
    return clean


def _comparison_rows(report: dict) -> list[dict]:
    return [
        {"method": method, "group": group.removeprefix("by_"), "group_value": value, **metrics}
        for method, groups in report["metrics"].items()
        for group, values in groups.items()
        for value, metrics in ({"all": values} if group == "overall" else values).items()
    ]


def _benchmark_csvs(report: dict) -> dict[str, str]:
    identity = {"benchmark_run_id": report.get("run_id"), "corpus_id": report.get("corpus_id"),
                "matrix_sha256": report.get("matrix_sha256")}
    return {
        "metrics.csv": _csv(
            (*identity, *(field for field, _ in _COMPARISON_COLUMNS)),
            [{**identity, **row} for row in _comparison_rows(report)],
        ),
        "case-results.csv": _csv(
            (*identity, "trial_run_id", "mode", "repeat", "id", "split", "actor", "operation", "resource",
             "expected_allowed", "expected_violation", "prediction", "baseline_prediction", "http_status",
             "duration_seconds", "reason"),
            [{**row, **identity} for row in report.get("results", [])],
        ),
    }


def _csv(columns: tuple[str, ...], rows: list[dict]) -> str:
    def cell(value: Any) -> Any:
        if isinstance(value, str) and (
            value.startswith(("\t", "\r", "\n")) or re.match(r"^[\s\x00-\x1f\x7f-\x9f\ufeff]*[=+\-@＝＋－＠]", value)
        ):
            return "'" + value
        return value

    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(columns)
    writer.writerows([cell(row.get(field)) for field in columns] for row in rows)
    return stream.getvalue()


def _sample_description(report: dict) -> str:
    counts = report["sample_counts"]
    return (f"Distinct scenarios: {counts['distinct_scenarios']}; "
            f"distinct mode cases (mode/case pairs): {counts['distinct_mode_cases']}; "
            f"attempted observations: {counts['attempted_observations']}.")


def _protocol_notice(report: dict) -> str:
    study = report.get("study_protocol")
    if study is None:
        return ""
    return (f"Frozen experiment: {study['definition']['protocol_id']}; "
            f"canonical definition SHA-256: {study['canonical_sha256']}. "
            "Checked at preflight only; not execution attestation or trusted preregistration. "
            "See the preserved definition in report.json.")


def _display_cell(field: str, value: Any) -> str:
    if field in _RATE_FIELDS:
        return "undefined" if value is None else f"{value:.1%}"
    return "" if value is None else str(value)


def _markdown_escape(value: Any) -> str:
    escaped = html.escape(str(value), quote=True).replace("\r", " ").replace("\n", "<br>")
    return re.sub(r"([\\`*_\[\]()|~])", r"\\\1", escaped)


def _markdown_table(columns: tuple[tuple[str, str], ...], rows: list[dict]) -> str:
    lines = ["| " + " | ".join(label for _, label in columns) + " |",
             "| " + " | ".join("---" for _ in columns) + " |"]
    lines.extend("| " + " | ".join(_markdown_escape(_display_cell(field, row.get(field)))
                                   for field, _ in columns) + " |" for row in rows)
    return "\n".join(lines)


def _html_table(caption: str, columns: tuple[tuple[str, str], ...], rows: list[dict]) -> str:
    header = "".join(f'<th scope="col">{html.escape(label)}</th>' for _, label in columns)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(_display_cell(field, row.get(field)), quote=True)}</td>"
                                   for field, _ in columns) + "</tr>" for row in rows)
    return (f'<div class="table-wrap" role="region" aria-label="{html.escape(caption, quote=True)}" tabindex="0">'
            f'<table><caption>{html.escape(caption)}</caption><thead><tr>{header}</tr></thead>'
            f'<tbody>{body}</tbody></table></div>')


def _markdown(report: dict) -> str:
    lines = [
        "# Aegis broken-access-control research", "",
        f"Run: {_markdown_escape(report.get('run_id', 'unknown'))}",
        f"Result: {_markdown_escape(report.get('status', 'error'))}", "",
        "Synthetic, owned loopback lab only. Signatures establish artifact integrity, not detection correctness or source attestation.", "",
    ]
    if report.get("kind") == "bac-benchmark":
        notice = _protocol_notice(report)
        if notice:
            lines.extend([_markdown_escape(notice), ""])
        lines.extend(["## Method comparison", "", _sample_description(report), "", _BENCHMARK_SCOPE, "",
                      _markdown_table(_COMPARISON_COLUMNS, _comparison_rows(report)), "",
                      "## Scenario outcomes", "", _markdown_table(_BENCHMARK_CASE_COLUMNS, report.get("results", [])), "",
                      "CSV downloads: [metrics.csv](metrics.csv) and [case-results.csv](case-results.csv).", ""])
    elif report.get("metrics"):
        lines.extend(["## Measurements", "", "```json", json.dumps(report["metrics"], indent=2), "```", ""])
    if report.get("kind") != "bac-benchmark":
        for item in report.get("results", []):
            lines.append(f"- {item.get('id')}: {item.get('status')} — {item.get('actor')} / {item.get('operation')} / {item.get('resource')}; {item.get('reason', '')}")
    lines.extend(["", "See report.json, evidence.json, server-events.json, matrix.json, and scan-manifest.json for the complete exported record.", ""])
    return "\n".join(lines)


def _html(report: dict) -> str:
    def escape(value: Any) -> str:
        return html.escape(str(value), quote=True)

    columns: tuple[tuple[str, str], ...] = (
        ("id", "Case"), ("status", "Outcome"), ("actor", "Actor"),
        ("operation", "Operation"), ("resource", "Resource"), ("reason", "Reason"),
    )
    downloads = ""
    comparison = ""
    if report.get("kind") == "bac-benchmark":
        columns = _BENCHMARK_CASE_COLUMNS
        downloads = ' · <a href="metrics.csv">Metrics CSV</a> · <a href="case-results.csv">Case results CSV</a>'
        notice = _protocol_notice(report)
        comparison = ((f'<p class="protocol-reference">{escape(notice)}</p>' if notice else '')
                      + f'<h2>Method comparison</h2><p>{escape(_sample_description(report))}</p>'
                      f'<p>{escape(_BENCHMARK_SCOPE)}</p>'
                      + _html_table("Method comparison", _COMPARISON_COLUMNS, _comparison_rows(report)))
        measurements = ""
    else:
        measurements = html.escape(json.dumps(report.get("metrics", report.get("methods", {})), indent=2))
        measurements = f"<h2>Measurements</h2><pre>{measurements}</pre>"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Aegis BAC research</title><style>body{font:16px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#182334}'
        'table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #ccc;padding:.6rem;vertical-align:top}'
        'pre{overflow:auto;background:#f3f5f7;padding:1rem}.table-wrap{overflow:auto}.protocol-reference{overflow-wrap:anywhere}</style></head><body>'
        '<h1>Aegis broken-access-control research</h1>'
        f'<p>Run: {escape(report.get("run_id", "unknown"))} · Result: {escape(report.get("status", "error"))}</p>'
        '<p>Synthetic, owned loopback lab only. Signatures establish artifact integrity—not detection correctness, source attestation, or real-world accuracy.</p>'
        '<nav aria-label="Evidence downloads"><a href="report.json">Complete report</a> · <a href="evidence.json">HTTP and state evidence</a> · '
        '<a href="server-events.json">Server events</a> · <a href="matrix.json">Permission matrix</a> · <a href="scan-manifest.json">Signed manifest</a>'
        + downloads + '</nav>' + comparison
        + _html_table("Scenario outcomes", columns, report.get("results", []))
        + measurements + '</body></html>'
    )
