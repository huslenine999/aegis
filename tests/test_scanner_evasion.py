"""A hostile repository tries every known way to hide code from the real scanners.

Each trick here once worked against Aegis; the scan must still block on all of them.
"""

import json
import os
import sys

import pytest

from app.cli import main
from app.scanners import find_runtime_executable

pytestmark = pytest.mark.skipif(not find_runtime_executable("semgrep"), reason="semgrep is not installed")


def test_hostile_repository_cannot_hide_code_from_the_standard_scan(tmp_path, monkeypatch):
    # Semgrep and Ruff exit abruptly; a covered child would leave a malformed coverage shard.
    for name in [key for key in os.environ if key.startswith("COV_CORE")]:
        monkeypatch.delenv(name)
    target = tmp_path / "repo"
    (target / "ignored").mkdir(parents=True)
    # Ruff: inline noqa, a .ignore file, and .gitignore inside a git work tree.
    (target / "noqa.py").write_text("def run(value):\n    return eval(value)  # noqa: S307\n")
    (target / "ignored" / "dotignore.py").write_text("def run(value):\n    return eval(value)\n")
    (target / "ignored" / ".ignore").write_text("dotignore.py\n")
    (target / "gitignored.py").write_text("def run(value):\n    return eval(value)\n")
    (target / ".gitignore").write_text("gitignored.py\n")
    # Semgrep: nosemgrep and a repository .semgrepignore.
    (target / "nosem.js").write_text("module.exports = (code) => eval(code); // nosemgrep\n")
    (target / "semgrepignored.js").write_text("module.exports = (code) => eval(code);\n")
    (target / ".semgrepignore").write_text("semgrepignored.js\n")
    # detect-secrets: an inline allowlist pragma.
    (target / "settings.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret\n')
    output = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["aegis", "scan", str(target), "--preset", "standard", "--output", str(output), "--json"])

    assert main() == 1

    def names(report, key):
        return {str(item[key]).rsplit("/", 1)[-1] for item in report}

    ruff = json.loads((output / "ruff-report.json").read_text())
    assert {"noqa.py", "dotignore.py", "gitignored.py"} <= names(ruff, "filename")
    semgrep = json.loads((output / "semgrep-report.json").read_text())["results"]
    assert {"nosem.js", "semgrepignored.js"} <= names(semgrep, "path")
    secrets = json.loads((output / "secrets-report.json").read_text())["results"]
    assert "settings.py" in secrets
