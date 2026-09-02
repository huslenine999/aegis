import hashlib
import hmac
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .artifact_storage import artifact_limits
from .cli_config import (
    DEFAULT_SCAN_DIR,
    EXIT_ALLOWED,
    EXIT_OPERATIONAL_ERROR,
    PROJECT_ROOT,
)
from .evidence import (
    classify_source_attestation,
    verify_manifest,
    verify_source_descriptor,
)
from .resource_budgets import (
    ResourceLimitError,
    iter_file_bytes,
    load_bounded_json,
)
from .safe_output import SafeOutputRoot
from .sandbox import is_docker_available
from .scanners import find_runtime_executable


def write_json(
    path: Path,
    data,
    *,
    safe_output: SafeOutputRoot | None = None,
):
    if safe_output is not None:
        safe_output.write_json_path(path, data)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary_path.write_text(f"{json.dumps(data, indent=2)}\n")
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def read_json(path: Path):
    try:
        return load_bounded_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ResourceLimitError):
        return None


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_sarif_report(
    path: Path,
    results: list[dict],
    base_path: Path | None = None,
    *,
    safe_output: SafeOutputRoot | None = None,
):
    severity_to_level = {
        "HIGH": "error",
        "CRITICAL": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    sarif_results = []
    rules: dict[str, dict] = {}

    for tool_result in results or []:
        tool_name = tool_result.get("tool", "Aegis")
        issues = tool_result.get("findings") if tool_result.get("tool") == "IaC" else tool_result.get("examples", [])
        for issue in issues or []:
            rule_id = str(issue.get("test_id") or issue.get("vulnerability_id") or issue.get("rule") or tool_name)
            message = str(issue.get("issue_text") or issue.get("description") or issue.get("package_name") or "Aegis finding")
            severity = str(issue.get("severity") or "MEDIUM").upper()
            filename = issue.get("filename") or issue.get("path") or "requirements.txt"
            artifact_uri = str(filename)
            if base_path:
                try:
                    artifact_uri = str(Path(artifact_uri).resolve().relative_to(base_path.resolve()))
                except ValueError:
                    artifact_uri = str(filename)
            line = issue.get("line_number") or issue.get("start_line") or 1
            end_line = issue.get("end_line") or line
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message[:120]},
            })
            sarif_results.append({
                "ruleId": rule_id,
                "level": severity_to_level.get(severity, "warning"),
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "region": {
                            "startLine": int(line) if str(line).isdigit() else 1,
                            "endLine": int(end_line) if str(end_line).isdigit() else int(line) if str(line).isdigit() else 1,
                        },
                    }
                }],
                "properties": {
                    "tool": tool_name,
                    "severity": severity,
                    **({
                        "framework": issue.get("framework"),
                        "resource": issue.get("resource"),
                        "unmanaged_suppression": bool(issue.get("unmanaged_suppression")),
                    } if tool_name == "IaC" else {}),
                },
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Aegis",
                    "informationUri": "https://github.com/huslenine999/aegis",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    write_json(path, sarif, safe_output=safe_output)


def run_doctor(json_output: bool = False) -> int:
    checks = []

    def add_check(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    add_check("python", True, sys.version.split()[0])
    add_check("project_root", PROJECT_ROOT.exists(), str(PROJECT_ROOT))
    add_check("ruff", True, "python module available")
    try:
        importlib.metadata.version("ruff")
    except importlib.metadata.PackageNotFoundError:
        checks[-1] = {"name": "ruff", "ok": False, "detail": "python module missing"}

    semgrep_bin = find_runtime_executable("semgrep")
    add_check("semgrep", semgrep_bin is not None, semgrep_bin or "not found")
    checkov_bin = find_runtime_executable("checkov")
    add_check("checkov", checkov_bin is not None, checkov_bin or "not found")
    trivy_bin = shutil.which("trivy")
    add_check("trivy", trivy_bin is not None, trivy_bin or "not found")
    cli_module = sys.modules.get("app.cli")
    docker_available = cli_module.is_docker_available() if cli_module else is_docker_available()
    add_check("docker", docker_available, "available" if docker_available else "unavailable")

    ok = all(check["ok"] for check in checks if check["name"] in {"python", "project_root", "ruff"})
    payload = {"status": "ok" if ok else "degraded", "checks": checks}

    if json_output:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Aegis doctor: {payload['status']}")
        for check in checks:
            marker = "OK" if check["ok"] else "WARN"
            print(f"  [{marker}] {check['name']}: {check['detail']}")
    return 0 if ok else 1


def find_report_file(report_dir: str | None = None, *, markdown: bool = False) -> Path | None:
    filename = "report.md" if markdown else "report.html"
    if report_dir:
        candidate = Path(report_dir).expanduser().resolve() / filename
        return candidate if candidate.exists() else None
    candidates = [
        Path.cwd() / DEFAULT_SCAN_DIR / filename,
        PROJECT_ROOT / DEFAULT_SCAN_DIR / filename,
        PROJECT_ROOT / "scans" / filename,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def open_report_file(path: Path) -> int:
    if sys.platform == "darwin":
        command = ["open", str(path)]
    elif os.name == "nt":
        command = ["cmd", "/c", "start", "", str(path)]
    else:
        command = ["xdg-open", str(path)]
    try:
        return subprocess.run(command, check=False).returncode
    except FileNotFoundError:
        return 1


def run_report(report_dir: str | None = None, *, markdown: bool = False, open_report: bool = False, path_only: bool = False) -> int:
    report_path = find_report_file(report_dir, markdown=markdown)
    if not report_path:
        searched = Path(report_dir).expanduser().resolve() if report_dir else Path.cwd() / DEFAULT_SCAN_DIR
        print(f"No Aegis report found. Run `aegis scan .` first or pass --dir. Checked: {searched}")
        return 1

    if path_only:
        print(report_path)
    else:
        print(f"Aegis report: {report_path}")

    if open_report:
        cli_module = sys.modules.get("app.cli")
        open_fn = cli_module.open_report_file if cli_module else open_report_file
        result = open_fn(report_path)
        if result != 0:
            print(f"Failed to open report automatically: {report_path}")
        return result
    return 0


def create_demo_target(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "app.py").write_text(
        "from flask import Flask, request\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.get('/calculate')\n"
        "def calculate():\n"
        "    return str("
        "eval("
        "request.args.get('expr', '1+1')))\n"
        "\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'status': 'ok'}\n"
    )
    (target_dir / "requirements.txt").write_text("Flask==3.1.3\n")
    (target_dir / "README.md").write_text(
        "# Aegis demo target\n\n"
        "This tiny app intentionally includes an unsafe `eval` route so Aegis can show a blocking finding quickly.\n"
    )


def run_demo(*, execute_scan_fn, open_report: bool = False, output_dir: str | None = None) -> int:
    demo_root = Path.cwd() / ".aegis"
    target_dir = demo_root / "demo-target"
    report_dir = Path(output_dir).expanduser().resolve() if output_dir else demo_root / "demo-report"
    create_demo_target(target_dir)

    print(f"Created demo target: {target_dir}")
    print("Running a quick local scan with Docker-dependent checks disabled...")
    try:
        summary = execute_scan_fn(
            str(target_dir),
            use_docker=False,
            output_dir=str(report_dir),
            fast=True,
            quiet=True,
            return_summary=True,
        )
    except Exception as exc:
        print(f"Aegis demo failed: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR

    status = summary.get("status", "unknown")
    report_path = Path(summary.get("html_report", report_dir / "report.html"))
    markdown_path = Path(summary.get("markdown_report", report_dir / "report.md"))
    print(f"Demo verdict: {status.upper()}")
    print(f"HTML report: {report_path}")
    print(f"Markdown report: {markdown_path}")
    print("The demo target intentionally contains an unsafe eval route, so a blocked verdict is expected.")

    if open_report:
        cli_module = sys.modules.get("app.cli")
        open_fn = cli_module.open_report_file if cli_module else open_report_file
        result = open_fn(report_path)
        if result != 0:
            print(f"Failed to open report automatically: {report_path}", file=sys.stderr)
            return result
    return 0


def hmac_compare_digest(first: str, second: str) -> bool:
    return hmac.compare_digest(first, second)


def run_verify_evidence(
    manifest_path: str,
    public_key: str | None = None,
    *,
    trust_embedded_key: bool = False,
) -> int:
    path = Path(manifest_path).expanduser().resolve()
    try:
        manifest = load_bounded_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ResourceLimitError) as exc:
        print(f"Evidence verification failed: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    if not public_key and not trust_embedded_key:
        print(
            "Evidence verification failed: --public-key is required. "
            "Use --trust-embedded-key only for non-authoritative local checks.",
            file=sys.stderr,
        )
        return EXIT_OPERATIONAL_ERROR
    if not isinstance(manifest, dict) or not verify_manifest(
        manifest, public_key, allow_embedded_key=trust_embedded_key
    ):
        print("Evidence verification failed: manifest signature is invalid.", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    for artifact in manifest.get("artifacts", []):
        name = str(artifact.get("name", ""))
        if Path(name).name != name:
            print("Evidence verification failed: unsafe artifact name.", file=sys.stderr)
            return EXIT_OPERATIONAL_ERROR
        artifact_path = path.parent / name
        try:
            content = b"".join(
                iter_file_bytes(
                    artifact_path,
                    max_bytes=artifact_limits()["per_artifact"],
                    chunk_size=1024 * 1024,
                )
            )
        except (OSError, ResourceLimitError):
            print(f"Evidence verification failed: missing artifact {name}.", file=sys.stderr)
            return EXIT_OPERATIONAL_ERROR
        if len(content) != int(artifact.get("size", -1)) or not hmac_compare_digest(
            hashlib.sha256(content).hexdigest(), str(artifact.get("sha256", ""))
        ):
            print(f"Evidence verification failed: artifact mismatch for {name}.", file=sys.stderr)
            return EXIT_OPERATIONAL_ERROR
    source_status = classify_source_attestation(manifest)
    if source_status == "invalid":
        print("Evidence verification failed: source attestation is invalid.", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    if source_status == "source-bound":
        if not any(
            isinstance(artifact, dict)
            and artifact.get("name") == "source-descriptor.json"
            for artifact in manifest.get("artifacts", [])
        ):
            print(
                "Evidence verification failed: source descriptor is not attested as an artifact.",
                file=sys.stderr,
            )
            return EXIT_OPERATIONAL_ERROR
        descriptor_path = path.parent / "source-descriptor.json"
        try:
            descriptor = load_bounded_json(descriptor_path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ResourceLimitError):
            print(
                "Evidence verification failed: source descriptor is missing or invalid.",
                file=sys.stderr,
            )
            return EXIT_OPERATIONAL_ERROR
        if not isinstance(descriptor, dict) or not verify_source_descriptor(manifest, descriptor):
            print("Evidence verification failed: source descriptor mismatch.", file=sys.stderr)
            return EXIT_OPERATIONAL_ERROR
    print(
        "Evidence verified: Ed25519 signature and "
        f"{len(manifest.get('artifacts', []))} artifact hashes are valid; "
        f"source attestation: {source_status}."
    )
    return EXIT_ALLOWED
