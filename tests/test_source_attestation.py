import os
import hashlib
import json

import pytest

from app.evidence import classify_source_attestation
from app.evidence import sign_manifest
from app import cli
from app.source_attestation import (
    SourceAttestationError,
    create_source_snapshot,
    normalize_scan_report_paths,
)
from app.safe_output import SafeOutputRoot


def test_source_snapshot_is_canonical_and_stable(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('safe')\n")
    (target / "excluded.py").write_text("print('excluded')\n")
    (target / ".venv").mkdir()
    (target / ".venv" / "runtime.py").write_text("print('ignored')\n")

    snapshot = create_source_snapshot(
        target,
        ignored_names={".venv"},
        excluded_paths={str(target / "excluded.py")},
    )
    try:
        assert snapshot.scan_path != target
        entry = snapshot.descriptor["files"][0]
        assert entry["mode"] == (target / "app.py").stat().st_mode & 0o777
        assert entry["path"] == "app.py"
        assert entry["size"] == 14
        assert len(snapshot.descriptor["files"]) == 1
        assert snapshot.descriptor_sha256
        assert snapshot.content_sha256

        (target / "app.py").write_text("print('changed after snapshot')\n")
        assert snapshot.scan_path.joinpath("app.py").read_text() == "print('safe')\n"
    finally:
        snapshot.cleanup()

    assert not snapshot.scan_path.exists()


def test_source_snapshot_rejects_mutating_or_unsupported_source(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "pipe").write_text("placeholder")
    (target / "pipe").unlink()
    os.mkfifo(target / "pipe")

    with pytest.raises(SourceAttestationError, match="regular files"):
        create_source_snapshot(target)


def test_legacy_manifests_are_distinguished_from_source_bound_manifests():
    legacy = {"schema_version": 2, "source": {"identity": "example"}}
    bound = {
        "schema_version": 3,
        "source": {
            "identity": "example",
            "attestation": {
                "schema_version": 1,
                "status": "source-bound",
                "method": "stable-copy",
                "descriptor_sha256": "a" * 64,
                "content_sha256": "b" * 64,
                "policy_sha256": "c" * 64,
            },
        },
    }

    assert classify_source_attestation(legacy) == "legacy-source-unbound"
    assert classify_source_attestation(bound) == "source-bound"


def test_source_bound_evidence_verifies_the_descriptor_artifact(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("print('safe')\n")
    snapshot = create_source_snapshot(target)
    try:
        descriptor_path = tmp_path / "source-descriptor.json"
        descriptor_path.write_text(json.dumps(snapshot.descriptor))
        manifest = sign_manifest(
            {
                "schema_version": 3,
                "source": snapshot.manifest_source(
                    identity=target.name,
                    revision="sha256:" + snapshot.descriptor["files"][0]["sha256"],
                    policy_sha256="c" * 64,
                ),
                "artifacts": [
                    {
                        "name": descriptor_path.name,
                        "size": descriptor_path.stat().st_size,
                        "sha256": hashlib.sha256(descriptor_path.read_bytes()).hexdigest(),
                    }
                ],
            }
        )
        manifest_path = tmp_path / "scan-manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        public_key = manifest["signature"]["public_key"]

        assert cli.run_verify_evidence(str(manifest_path), public_key) == 0
        descriptor_path.write_text("{}")
        assert cli.run_verify_evidence(str(manifest_path), public_key) == 2
    finally:
        snapshot.cleanup()


def test_snapshot_report_normalization_handles_path_keys(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('safe')\n")
    snapshot = create_source_snapshot(target)
    output = SafeOutputRoot(tmp_path / "reports")
    try:
        output.write_json(
            "secrets-report.json",
            {"results": {str(snapshot.scan_path / "app.py"): [{"type": "key"}]}},
        )
        normalize_scan_report_paths(output.root, snapshot, output)
        report = json.loads((output.root / "secrets-report.json").read_text())
        assert str(target / "app.py") in report["results"]
    finally:
        snapshot.cleanup()
