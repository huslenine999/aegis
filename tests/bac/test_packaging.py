"""The bundled corpus must survive both supported distribution paths."""

import json
import tomllib
from pathlib import Path


def test_default_matrix_is_in_python_and_npm_package_data():
    root = Path(__file__).resolve().parents[2]
    python = tomllib.loads((root / "pyproject.toml").read_text())
    node = json.loads((root / "package.json").read_text())
    assert "*.json" in python["tool"]["setuptools"]["package-data"]["rules"]
    assert "rules/" in node["files"]


def test_bac_modules_are_in_standard_type_and_coverage_gates():
    root = Path(__file__).resolve().parents[2]
    config = tomllib.loads((root / "pyproject.toml").read_text())
    makefile = (root / "Makefile").read_text()
    for name in ("bac", "bac_config", "bac_lab", "bac_reports", "bac_benchmark"):
        assert f"app/{name}.py" in config["tool"]["mypy"]["files"]
        assert f"app.{name}" in config["tool"]["coverage"]["run"]["source"]
        assert f"--cov=app.{name}" in makefile
