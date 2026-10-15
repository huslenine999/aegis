"""Rule-level checks for rules/semgrep_rules.yaml against labeled fixtures."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

import policy_engine
from app import cli
from app.scan_engine import SEMGREP_SOURCE_EXTENSIONS, add_semgrep_excludes
from app.scanners import find_runtime_executable, semgrep_coverage_gaps

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "semgrep_rules.yaml"
FIXTURES = ROOT / "tests" / "fixtures" / "semgrep"
ANNOTATION = re.compile(r"(ruleid|ok): ([\w-]+)")
LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "java": ".java",
}


def load_rules():
    return yaml.safe_load(RULES.read_text())["rules"]


def fixture_labels():
    expected, safe = set(), set()
    for path in sorted(FIXTURES.iterdir()):
        if path.suffix == ".md":
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            match = ANNOTATION.search(line)
            if match:
                target = expected if match[1] == "ruleid" else safe
                target.add((path.name, number + 1, match[2]))
    return expected, safe


def test_rule_ids_are_unique_and_dot_free():
    ids = [rule["id"] for rule in load_rules()]

    assert len(ids) == len(set(ids))
    # policy_engine.semgrep_rule_id() relies on rule IDs having no dots.
    assert not [rule_id for rule_id in ids if "." in rule_id]


def test_every_rule_has_a_positive_fixture():
    expected, _ = fixture_labels()
    covered = {rule_id for _, _, rule_id in expected}

    assert {rule["id"] for rule in load_rules()} <= covered


def test_every_rule_language_is_routed_to_semgrep():
    languages = {language for rule in load_rules() for language in rule["languages"]}

    assert languages <= set(LANGUAGE_EXTENSIONS)
    assert {LANGUAGE_EXTENSIONS[language] for language in languages} <= SEMGREP_SOURCE_EXTENSIONS


def test_semgrep_rule_id_strips_machine_specific_prefix():
    assert policy_engine.semgrep_rule_id("Users.alice.site-packages.rules.go-weak-hash") == "go-weak-hash"
    assert policy_engine.semgrep_rule_id("go-weak-hash") == "go-weak-hash"
    result = policy_engine.analyze_semgrep({"results": [{
        "check_id": "home.bob.rules.java-xxe",
        "path": "A.java",
        "start": {"line": 3},
        "extra": {"severity": "WARNING", "message": "XXE"},
    }]})
    assert result["examples"][0]["test_id"] == "java-xxe"


def test_semgrep_suppression_matches_bare_rule_id(tmp_path):
    scan_dir = tmp_path / "reports"
    scan_dir.mkdir()
    (scan_dir / "semgrep-report.json").write_text(json.dumps({"results": [{
        "check_id": "Users.alice.aegis.rules.javascript-xss-html-sink",
        "path": str(tmp_path / "web" / "app.js"),
        "start": {"line": 4},
        "extra": {"severity": "WARNING"},
    }]}))
    suppressions = cli.normalize_suppressions({"scan": {"suppressions": [{
        "tool": "Semgrep",
        "rule": "javascript-xss-html-sink",
        "path": "web/app.js",
        "reason": "Markup is built only from escaped labels and numbers.",
        "approved_by": "application-security",
        "ticket": "SEC-9",
        "expires_at": "2099-12-31",
    }]}}, tmp_path)

    cli.apply_suppressions(scan_dir, suppressions)

    assert json.loads((scan_dir / "semgrep-report.json").read_text())["results"] == []


@pytest.mark.skipif(not find_runtime_executable("semgrep"), reason="semgrep is not installed")
def test_rules_match_labeled_fixtures_exactly(tmp_path):
    # Semgrep's default ignore list skips tests/, so scan a copy.
    target = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, target)
    completed = subprocess.run(
        [
            find_runtime_executable("semgrep"), "scan", "--metrics", "off", "--disable-version-check",
            "--config", str(RULES), "--json", "--quiet", str(target),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    report = json.loads(completed.stdout)
    assert report["errors"] == []
    found = {
        (Path(item["path"]).name, item["start"]["line"], policy_engine.semgrep_rule_id(item["check_id"]))
        for item in report["results"]
    }
    expected, safe = fixture_labels()

    assert sorted(expected - found) == [], "missed labeled vulnerabilities"
    assert sorted(found - expected) == [], "findings on unlabeled or ok lines"
    assert not found & safe


@pytest.mark.skipif(not find_runtime_executable("semgrep"), reason="semgrep is not installed")
def test_scanned_repository_cannot_choose_what_semgrep_skips(tmp_path):
    target = tmp_path / "repo"
    (target / "tests").mkdir(parents=True)
    (target / "hidden.py").write_text("def run(value):\n    return eval(value)  # nosemgrep\n")
    (target / "ignored.py").write_text("def run(value):\n    return eval(value)\n")
    (target / "tests" / "fixture.py").write_text("def run(value):\n    return eval(value)\n")
    (target / ".semgrepignore").write_text("ignored.py\nhidden.py\n")
    command = [find_runtime_executable("semgrep"), "scan", "--metrics", "off", "--disable-version-check",
               "--config", str(RULES), "--json", "--quiet"]
    completed = subprocess.run(
        add_semgrep_excludes(command) + [str(target)], capture_output=True, text=True, timeout=300, check=False,
    )
    found = {Path(item["path"]).name for item in json.loads(completed.stdout)["results"]}
    # nosemgrep comments and .semgrepignore are ignored; Semgrep's own default
    # (skip tests/) is now applied by Aegis instead.
    assert found == {"hidden.py", "ignored.py"}


def test_semgrep_timeouts_and_fatal_errors_are_coverage_gaps():
    report = {"errors": [
        {"level": "warn", "type": "Timeout", "path": "big.py", "rule_id": "python-eval"},
        {"level": "warn", "type": "Timeout", "path": "big.py", "rule_id": "python-rce"},
        {"level": "warn", "type": ["PartialParsing", [{"path": "broken.py"}]], "path": "broken.py"},
        {"level": "error", "type": "Fatal error", "path": "other.js"},
        "not-an-object",
    ]}
    assert semgrep_coverage_gaps(report) == ["Fatal error in other.js", "Timeout in big.py"]
    assert semgrep_coverage_gaps({"errors": [], "results": []}) == []
