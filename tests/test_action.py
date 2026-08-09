import json
import subprocess
import os
import re
import tomllib
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTION_PATH = PROJECT_ROOT / "action.yml"
WORKFLOWS_PATH = PROJECT_ROOT / ".github" / "workflows"
IMMUTABLE_ACTION_REF = re.compile(
    r"^\s*uses:\s*(?P<action>[^@\s]+)@(?P<ref>[0-9a-f]{40})(?:\s+#.*)?$"
)


def load_action():
    return yaml.safe_load(ACTION_PATH.read_text())


def test_action_exposes_stable_production_outputs():
    action = load_action()

    assert action["inputs"]["strict"]["default"] == "true"
    assert set(action["outputs"]) >= {"decision", "summary-json", "exit-code"}
    action_text = ACTION_PATH.read_text()
    assert '--require-hashes -r "${AEGIS_ACTION_PATH}/requirements.txt"' in action_text
    assert 'pip install --no-deps "${AEGIS_ACTION_PATH}"' in action_text


def test_release_package_versions_match():
    python_version = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text()
    )["project"]["version"]
    npm_version = json.loads(
        (PROJECT_ROOT / "package.json").read_text()
    )["version"]
    lock_version = tomllib.loads((PROJECT_ROOT / "uv.lock").read_text())["package"][0]["version"]

    assert python_version == npm_version == lock_version


def test_npm_manifest_excludes_runtime_state():
    package = json.loads((PROJECT_ROOT / "package.json").read_text())

    assert "app/" not in package["files"]
    assert set(package["files"]) >= {
        "app/*.py",
        "app/downloads/",
        "app/static/",
        "app/templates/",
    }


def test_all_external_actions_use_immutable_commit_shas():
    action_files = [ACTION_PATH, *sorted(WORKFLOWS_PATH.glob("*.yml"))]

    for path in action_files:
        uses_lines = [
            line
            for line in path.read_text().splitlines()
            if line.lstrip().startswith("uses:")
        ]
        assert uses_lines, f"{path} does not contain an Action reference"
        for line in uses_lines:
            assert IMMUTABLE_ACTION_REF.match(line), (
                f"{path} contains a mutable or local Action reference: {line.strip()}"
            )


def test_container_release_workflows_pin_buildx_setup():
    expected = (
        "uses: docker/setup-buildx-action@"
        "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4.2.0"
    )

    for name in ("release-build.yml", "container-release.yml"):
        assert expected in (WORKFLOWS_PATH / name).read_text()


def test_manual_container_release_checks_out_validated_tag():
    workflow_path = WORKFLOWS_PATH / "container-release.yml"
    workflow = yaml.safe_load(workflow_path.read_text())
    job = workflow["jobs"]["publish-container"]
    checkout = next(
        step for step in job["steps"] if step.get("name") == "Checkout tagged source"
    )
    validation = next(
        step
        for step in job["steps"]
        if step.get("name") == "Validate release tag and package version"
    )
    publish = next(
        step
        for step in job["steps"]
        if step.get("name") == "Publish versioned container image"
    )

    assert job["environment"] == "container-release"
    assert checkout["with"]["ref"] == "${{ inputs.release_tag }}"
    assert 're.fullmatch(r"v[0-9]+\\.[0-9]+\\.[0-9]+"' in validation["run"]
    assert "version != python_version or version != npm_version" in validation["run"]
    assert '-t "$IMAGE:$VERSION"' in publish["run"]
    assert '-t "$IMAGE:latest"' in publish["run"]


def test_repository_has_no_tracked_absolute_symlinks():
    tracked_files = subprocess.run(
        ["git", "ls-files", "-s"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    symlink_paths = [
        line.split("\t", 1)[1]
        for line in tracked_files
        if line.startswith("120000 ")
    ]

    absolute_symlinks = []
    for relative_path in symlink_paths:
        target = os.readlink(PROJECT_ROOT / relative_path)
        if os.path.isabs(target):
            absolute_symlinks.append((relative_path, target))

    assert not absolute_symlinks, (
        f"tracked absolute symlinks are not portable: {absolute_symlinks}"
    )


def test_redis_runtime_starts_as_its_unprivileged_user():
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())
    redis_service = compose["services"]["redis"]

    assert redis_service["user"] == "999:1000"
    assert redis_service["cap_drop"] == ["ALL"]
    assert "cap_add" not in redis_service


def test_security_gate_uses_trusted_scanner_and_policy_revision():
    workflow = (WORKFLOWS_PATH / "security-pipeline.yml").read_text()

    assert "uses: ./" not in workflow
    assert "ref: 1d60daa9efa001eb36716e5656db514f809b8b6d" in workflow
    assert "python -m pip install ./trusted-aegis" in workflow
    assert "cp trusted-aegis/aegis.yml target/.aegis-trusted.yml" in workflow
    assert "--config target/.aegis-trusted.yml" in workflow
    assert "aegis scan target" in workflow
    assert "--disable-version-check" in workflow
    assert "--validate" in workflow


def test_security_gate_shell_script_has_valid_bash_syntax(tmp_path):
    workflow = yaml.safe_load(
        (WORKFLOWS_PATH / "security-pipeline.yml").read_text()
    )
    scan_step = next(
        step
        for step in workflow["jobs"]["security-gate"]["steps"]
        if step.get("name") == "Run trusted Aegis approval scan"
    )
    script_path = tmp_path / "security-gate.sh"
    script_path.write_text(scan_step["run"])

    result = subprocess.run(
        ["bash", "-n", str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_container_smoke_starts_all_readiness_services():
    workflow = yaml.safe_load(
        (WORKFLOWS_PATH / "security-pipeline.yml").read_text()
    )
    steps = workflow["jobs"]["container-smoke"]["steps"]
    start_step = next(step for step in steps if step.get("name") == "Start production stack")
    log_step = next(step for step in steps if step.get("name") == "Show container logs")

    required_services = {"postgres", "redis", "dashboard", "worker", "notifier"}
    assert required_services <= set(start_step["run"].split())
    assert required_services <= set(log_step["run"].split())


def test_published_action_e2e_asserts_outputs_and_reports():
    workflow = (WORKFLOWS_PATH / "action-e2e.yml").read_text()

    assert "huslenine999/aegis@e292c60770bee621fb70ba07b71cc9f2a525ea1a" in workflow
    assert "steps.aegis.outputs.decision" in workflow
    assert "steps.aegis.outputs.exit-code" in workflow
    assert "steps.aegis.outputs.summary-json" in workflow
    assert "action-e2e-reports/scan-manifest.json" in workflow


def test_action_passes_inputs_through_environment_and_bash_array():
    action = load_action()
    scan_step = next(step for step in action["runs"]["steps"] if step.get("id") == "aegis")
    script = scan_step["run"]

    assert scan_step["env"]["INPUT_TARGET"] == "${{ inputs.scan-target }}"
    assert "ARGS=(" in script
    assert 'scan "$INPUT_TARGET"' in script
    assert 'aegis "${ARGS[@]}"' in script
    assert "${{ inputs.scan-target }}" not in script
    assert "${{ inputs.output-dir }}" not in script


def test_action_shell_script_has_valid_bash_syntax(tmp_path):
    action = load_action()
    scan_step = next(step for step in action["runs"]["steps"] if step.get("id") == "aegis")
    script_path = tmp_path / "action-step.sh"
    script_path.write_text(scan_step["run"])

    result = subprocess.run(
        ["bash", "-n", str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_action_invalid_input_sets_error_outputs(tmp_path):
    action = load_action()
    scan_step = next(step for step in action["runs"]["steps"] if step.get("id") == "aegis")
    script_path = tmp_path / "action-step.sh"
    output_path = tmp_path / "github-output"
    summary_path = tmp_path / "github-summary"
    script_path.write_text(scan_step["run"])
    environment = {
        **os.environ,
        "INPUT_TARGET": ".",
        "INPUT_OUTPUT_DIR": "reports",
        "INPUT_NO_DOCKER": "true",
        "INPUT_TIMEOUT": "not-a-number",
        "INPUT_FAIL_ON": "high,critical",
        "INPUT_CONFIG": "",
        "INPUT_SARIF": "false",
        "INPUT_STRICT": "true",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(output_path),
        "GITHUB_STEP_SUMMARY": str(summary_path),
    }

    result = subprocess.run(
        ["bash", str(script_path)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    outputs = output_path.read_text()
    assert "decision=error" in outputs
    assert "exit-code=2" in outputs
    assert (tmp_path / "aegis-input-error.json").exists()
