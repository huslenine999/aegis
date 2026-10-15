"""Property-based fuzzing of parsers that read untrusted or third-party input.

Deeper runs: AEGIS_FUZZ_EXAMPLES=5000 pytest tests/test_fuzz_inputs.py (random, with a
local example database). The default run is small and derandomized for CI.
"""

import json
import os
import re
import time

from hypothesis import HealthCheck, given, settings, strategies as st

import policy_engine
from app.dependencies import extract_packages_from_manifest
from app.evidence import (
    classify_source_attestation,
    evidence_public_key,
    sign_manifest,
    verify_manifest,
    verify_source_descriptor,
)
from app.findings import osv_base_severity

DEEP = "AEGIS_FUZZ_EXAMPLES" in os.environ
fuzz = settings(
    max_examples=int(os.environ.get("AEGIS_FUZZ_EXAMPLES", "120")),
    deadline=None,
    derandomize=not DEEP,
    database=None if not DEEP else settings.default.database,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=30),
    lambda children: st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=10), children, max_size=5),
    max_leaves=20,
)
MANIFESTS = ["requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock", "package.json",
             "package-lock.json", "pnpm-lock.yaml", "yarn.lock"]


def is_exact(version):
    return bool(re.fullmatch(r"[0-9][0-9A-Za-z.!+_-]*", version)) and not re.search(r"(^|\.)[xX*](\.|$)", version)


def parse(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8", "surrogatepass"))
    return extract_packages_from_manifest(path, raise_errors=True)


# --- dependency manifests --------------------------------------------------

names = st.from_regex(r"[A-Za-z][A-Za-z0-9_.-]{0,14}[A-Za-z0-9]|[A-Za-z]", fullmatch=True)
versions = st.one_of(
    st.tuples(st.from_regex(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}(rc[0-9])?", fullmatch=True), st.just(True)),
    st.tuples(st.sampled_from(["2.*", "1.x", "1.2.X", "*", "latest", "next", "beta", "dev"]), st.just(False)),
)
operators = st.sampled_from(["==", "===", "!=", "~=", ">=", "<=", ">", "<"])


@fuzz
@given(st.lists(st.tuples(
    names, st.sampled_from(["", "[security]", "[a,b]"]),
    st.lists(st.tuples(operators, versions), max_size=3),
    st.sampled_from(["", " ; python_version < '3.12'", "  # pinned", " --hash=sha256:" + "0" * 64]),
), min_size=1, max_size=6))
def test_requirements_record_every_package_and_only_exact_pins(tmp_path_factory, lines):
    text = "\n".join(
        name + extras + ", ".join(operator + version for operator, (version, _) in clauses) + suffix
        for name, extras, clauses, suffix in lines
    )
    packages = parse(tmp_path_factory.mktemp("req"), "requirements.txt", text)
    assert [package.name for package in packages] == [name for name, *_ in lines]
    for package, (_, _, clauses, _) in zip(packages, lines):
        pinned = len(clauses) == 1 and clauses[0][0] in {"==", "==="} and clauses[0][1][1]
        assert package.version == (clauses[0][1][0] if pinned else None), text


@fuzz
@given(st.sampled_from(MANIFESTS), st.text(max_size=400) | st.binary(max_size=400))
def test_manifest_parsers_fail_or_return_exact_versions_quickly(tmp_path_factory, name, content):
    started = time.monotonic()
    try:
        packages = parse(tmp_path_factory.mktemp("manifest"), name, content)
    except Exception:  # noqa: BLE001 - any parse error is recorded and fails the inventory closed
        packages = []
    assert time.monotonic() - started < 2
    assert all(is_exact(package.version) for package in packages if package.version is not None)


@fuzz
@given(st.sampled_from(["package.json", "package-lock.json", "pyproject.toml", "uv.lock"]),
       st.dictionaries(st.sampled_from(["dependencies", "devDependencies", "packages", "project", "package",
                                        "tool", "optionalDependencies"]), json_values, max_size=4))
def test_structured_manifests_never_invent_exact_versions(tmp_path_factory, name, document):
    if name.endswith(".json"):
        content = json.dumps(document)
    else:
        content = "\n".join(f"{key} = {json.dumps(value)}" for key, value in document.items()
                            if isinstance(value, (str, int, bool)))
    try:
        packages = parse(tmp_path_factory.mktemp("structured"), name, content)
    except Exception:  # noqa: BLE001
        return
    assert all(is_exact(package.version) for package in packages if package.version is not None)


def test_floating_and_tagged_specs_are_not_treated_as_pins(tmp_path):
    packages = parse(tmp_path, "package.json", json.dumps({"dependencies": {
        "a": "latest", "b": "1.x", "c": "*", "d": "1.2.3", "e": "v2.0.0", "f": "=3.1.0", "g": "^1.0.0",
    }}))
    assert {package.name: package.version for package in packages} == {
        "a": None, "b": None, "c": None, "d": "1.2.3", "e": "2.0.0", "f": "3.1.0", "g": None,
    }
    pyproject = parse(tmp_path, "pyproject.toml", '[project]\ndependencies = ["requests", "flask==2.*", "rich==13.7.1"]\n')
    assert [(package.name, package.version) for package in pyproject] == [
        ("requests", None), ("flask", None), ("rich", "13.7.1"),
    ]


# --- advisory scoring ------------------------------------------------------

@fuzz
@given(st.text(max_size=120) | st.lists(st.sampled_from(
    ["CVSS:3.1", "CVSS:4.0", "AV:N", "AV:X", "AC:L", "PR:H", "UI:R", "S:C", "S:U", "C:H", "I:L", "A:N",
     "Au:N", "C:P", "C:C", "VC:H", "::", "/", ""]), max_size=12).map("/".join))
def test_cvss_parser_is_total_and_bounded(vector):
    score = policy_engine.parse_cvss_vector(vector)
    assert isinstance(score, float) and 0.0 <= score <= 10.0


def test_cvss_scores_match_the_specifications():
    assert policy_engine.parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert policy_engine.parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") == 6.4
    assert policy_engine.parse_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") == 7.5
    assert policy_engine.parse_cvss_vector("AV:L/AC:H/Au:M/C:N/I:N/A:C") == 3.7
    assert policy_engine.parse_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == 0.0


@fuzz
@given(st.dictionaries(st.sampled_from(["id", "aliases", "severity", "database_specific", "summary", "details"]),
                       json_values, max_size=6))
def test_osv_advisory_normalization_is_total(record):
    try:
        normalized = policy_engine._normalize_osv_advisory(record)
    except (AttributeError, TypeError):
        # aliases/severity of the wrong JSON type: the hydration step records a failed advisory.
        return
    score = normalized["cvss"]
    assert score is None or isinstance(score, (int, float, str))
    assert osv_base_severity(score) in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_unscored_and_v4_only_advisories_block_by_default():
    v4_only = policy_engine._normalize_osv_advisory({"id": "GHSA-v4", "severity": [
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]})
    rated = policy_engine._normalize_osv_advisory({"id": "GHSA-rated", "database_specific": {"severity": "CRITICAL"},
                                                   "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]})
    legacy = policy_engine._normalize_osv_advisory({"id": "PYSEC-v2", "severity": [
        {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]})
    assert v4_only["cvss"] is None and rated["cvss"] == 9.0 and legacy["cvss"] == 10.0
    result = policy_engine.analyze_osv([{**v4_only, "package": "a", "version": "1.0.0"}])
    assert result["examples"][0]["severity"] == "MEDIUM" and result["blocking_issues"] == 1
    assert "no CVSS" in result["examples"][0]["severity_reason"]


# --- signed evidence -------------------------------------------------------

@fuzz
@given(json_values)
def test_manifest_verification_never_raises(value):
    key = evidence_public_key()["public_key"]
    assert verify_manifest(value, key) is False
    assert classify_source_attestation(value) in {"invalid", "legacy-source-unbound", "source-bound"}
    assert verify_source_descriptor(value, value) in {True, False}


@fuzz
@given(st.dictionaries(st.text(max_size=8), json_values, min_size=1, max_size=6), st.data())
def test_any_change_to_a_signed_manifest_breaks_its_signature(payload, data):
    key = evidence_public_key()["public_key"]
    signed = sign_manifest(payload)
    assert verify_manifest(signed, key)
    field = data.draw(st.sampled_from(sorted(set(signed) - {"signature"})))
    replacement = data.draw(json_values.filter(lambda value: value != signed[field]))
    assert not verify_manifest({**signed, field: replacement}, key)
