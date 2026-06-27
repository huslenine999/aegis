import subprocess
import os
import re
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


def test_security_gate_uses_trusted_scanner_and_policy_revision():
    workflow = (WORKFLOWS_PATH / "security-pipeline.yml").read_text()

    assert "uses: ./" not in workflow
    assert "ref: 5725dcb63ebe0f0eac070c2b908ec6f1cd1a45ff" in workflow
    assert "python -m pip install ./trusted-aegis" in workflow
    assert "--config trusted-aegis/aegis.yml" in workflow
    assert "aegis scan target" in workflow


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


def test_published_action_e2e_asserts_outputs_and_reports():
    workflow = (WORKFLOWS_PATH / "action-e2e.yml").read_text()

    assert "huslenine999/aegis@5725dcb63ebe0f0eac070c2b908ec6f1cd1a45ff" in workflow
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
