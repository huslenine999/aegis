import json

from app.dependencies import discover_dependency_manifests, first_requirements_manifest
from policy_engine import generate_cyclonedx_sbom, run_policy_engine


def test_dependency_discovery_supports_python_and_npm_manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.1.3\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests==2.34.2", "httpx>=0.28.1"]\n'
    )
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
        }
    }))
    node_modules = tmp_path / "node_modules" / "ignored"
    node_modules.mkdir(parents=True)
    (node_modules / "package.json").write_text(json.dumps({"dependencies": {"ignored": "1.0.0"}}))

    manifests = discover_dependency_manifests(tmp_path)
    packages = {(package.ecosystem, package.name, package.version) for manifest in manifests for package in manifest.packages}

    assert first_requirements_manifest(manifests).path == tmp_path / "requirements.txt"
    assert ("PyPI", "Flask", "3.1.3") in packages
    assert ("PyPI", "requests", "2.34.2") in packages
    assert ("npm", "lodash", "4.17.21") in packages
    assert not any(package.name == "ignored" for manifest in manifests for package in manifest.packages)


def test_sbom_includes_discovered_manifest_ecosystems(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.1.3\n")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}))
    sbom_path = tmp_path / "sbom.json"

    generate_cyclonedx_sbom(discover_dependency_manifests(tmp_path), sbom_path)

    components = json.loads(sbom_path.read_text())["components"]
    purls = {component["purl"] for component in components}
    assert "pkg:pypi/flask@3.1.3" in purls
    assert "pkg:npm/lodash@4.17.21" in purls


def test_policy_engine_does_not_fallback_to_aegis_requirements(tmp_path, monkeypatch):
    scan_dir = tmp_path / "scans"
    scan_dir.mkdir()
    for filename, payload in {
        "ruff-report.json": [],
        "safety-report.json": [],
        "trivy-report.json": {"Results": []},
        "secrets-report.json": {"results": {}},
        "yara-report.json": [],
        "semgrep-report.json": {"results": []},
        "clamav-report.json": [],
        "zap-report.json": [],
    }.items():
        (scan_dir / filename).write_text(json.dumps(payload))

    monkeypatch.delenv("AEGIS_TARGET_PATH", raising=False)
    exit_code = run_policy_engine(scan_dir)

    sbom = json.loads((scan_dir / "sbom.json").read_text())
    osv_report = json.loads((scan_dir / "osv-report.json").read_text())
    assert exit_code == 0
    assert sbom["components"] == []
    assert osv_report == []
