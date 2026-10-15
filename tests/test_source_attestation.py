import os
import hashlib
import json
from pathlib import Path

import pytest

from app.evidence import classify_source_attestation
from app.evidence import canonical_json
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


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_snapshot_hashes_preserve_canonical_json_with_unicode_filename(tmp_path, kind):
    target = tmp_path / ("한글.py" if kind == "file" else "source")
    if kind == "directory":
        target.mkdir()
        source_file = target / "한글.py"
        (target / "a.py").write_bytes(b"print('ascii')\n")
    else:
        source_file = target
    source_file.write_bytes("print('안전')\n".encode("utf-8"))
    snapshot = create_source_snapshot(target)
    try:
        descriptor = snapshot.descriptor
        legacy_json = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        assert canonical_json(descriptor) == legacy_json
        assert "한글.py".encode("utf-8") in legacy_json
        assert descriptor["root_kind"] == kind
        assert [entry["path"] for entry in descriptor["files"]] == (["한글.py"] if kind == "file" else ["a.py", "한글.py"])
        assert snapshot.descriptor_sha256 == hashlib.sha256(legacy_json).hexdigest()
        content = {"schema_version": 1, "files": [
            {key: entry[key] for key in ("path", "sha256", "size")}
            for entry in descriptor["files"]
        ]}
        content_json = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        assert snapshot.content_sha256 == hashlib.sha256(content_json).hexdigest()
    finally:
        snapshot.cleanup()


@pytest.mark.parametrize("kind", ["file", "directory"])
@pytest.mark.parametrize("remove_source", [False, True])
def test_snapshot_cleanup_only_removes_snapshot_and_is_idempotent(tmp_path, monkeypatch, kind, remove_source):
    import app.source_attestation as attestation

    temporary = tmp_path / "temporary"
    temporary.mkdir()
    make_tempdir = attestation.tempfile.mkdtemp
    monkeypatch.setattr(attestation.tempfile, "mkdtemp", lambda **kwargs: make_tempdir(dir=temporary, **kwargs))
    target = tmp_path / "source.py" if kind == "file" else tmp_path / "source"
    if kind == "directory":
        target.mkdir()
    source_file = target if kind == "file" else target / "app.py"
    source_file.write_text("print('safe')\n")
    nearby = tmp_path / "user-owned.txt"
    nearby.write_text("keep source neighbor")
    temporary_neighbor = temporary / "user-owned.txt"
    temporary_neighbor.write_text("keep snapshot neighbor")
    snapshot = create_source_snapshot(target)
    snapshot_root = snapshot.scan_path.parent if kind == "file" else snapshot.scan_path
    assert snapshot_root.parent == temporary.resolve()
    if remove_source:
        source_file.unlink()
        if kind == "directory":
            target.rmdir()

    snapshot.cleanup()
    snapshot.cleanup()

    assert not snapshot_root.exists()
    assert not snapshot.scan_path.exists()
    assert nearby.read_text() == "keep source neighbor"
    assert temporary_neighbor.read_text() == "keep snapshot neighbor"
    assert target.exists() is not remove_source
    if not remove_source:
        assert source_file.read_text() == "print('safe')\n"


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


def test_snapshot_resolves_exclusions_once_per_source_descriptor_pass(tmp_path, monkeypatch):
    target = tmp_path / "source"
    target.mkdir()
    for index in range(8):
        (target / f"app-{index}.py").write_text("pass\n")
    excludes = (target / "excluded-1.py", target / "excluded-2.py")
    resolve = Path.resolve
    calls = []

    def counted_resolve(path, *args, **kwargs):
        if path in excludes:
            calls.append(path)
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", counted_resolve)
    snapshot = create_source_snapshot(target, excluded_paths=excludes)
    try:
        assert snapshot.file_count == 8
        assert calls.count(excludes[0]) == 2
        assert calls.count(excludes[1]) == 2
    finally:
        snapshot.cleanup()


def test_snapshot_excludes_exact_files_and_directory_descendants(tmp_path):
    target = tmp_path / "source"
    (target / "excluded" / "nested").mkdir(parents=True)
    (target / "excluded-sibling").mkdir()
    for name in ("one.py", "one.py.backup", "excluded/nested/app.py", "excluded-sibling/app.py"):
        (target / name).write_text("pass\n")
    snapshot = create_source_snapshot(target, excluded_paths=("one.py", str(target / "excluded")))
    try:
        assert [item["path"] for item in snapshot.descriptor["files"]] == ["excluded-sibling/app.py", "one.py.backup"]
    finally:
        snapshot.cleanup()


def test_snapshot_still_rejects_source_changes_during_copy(tmp_path, monkeypatch):
    import app.source_attestation as attestation

    target = tmp_path / "source.py"
    target.write_text("original\n")
    copy = attestation._copy_regular_file

    def copy_then_change(source, destination, mode):
        copy(source, destination, mode)
        source.write_text("changed\n")

    monkeypatch.setattr(attestation, "_copy_regular_file", copy_then_change)
    with pytest.raises(SourceAttestationError, match="Source changed"):
        create_source_snapshot(target)


def test_snapshot_rejects_symlinks_even_when_excluded(tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("pass\n")
    (target / "excluded.py").symlink_to(outside)
    with pytest.raises(SourceAttestationError, match="symbolic links"):
        create_source_snapshot(target, excluded_paths=("excluded.py",))
