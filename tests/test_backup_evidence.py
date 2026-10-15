"""Backups record which evidence verified; restores refuse evidence that no longer does."""

import hashlib
import json
import shutil
import zipfile

import pytest

from app.cli_stack import EXIT_OPERATIONAL_ERROR, evidence_public_key_from_env, run_backup, run_restore
from app.evidence import evidence_public_key, sign_manifest
from tests.test_cli import DEVELOPMENT_SEED, _stack_stub


def signed_run(directory, content="decision: ALLOWED\n"):
    directory.mkdir(parents=True)
    report = directory / "report.md"
    report.write_text(content)
    data = report.read_bytes()
    manifest = sign_manifest({
        "schema_version": 2,
        "artifacts": [{"name": "report.md", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}],
    })
    (directory / "scan-manifest.json").write_text(json.dumps(manifest))


def scans_tree(root):
    signed_run(root / "tenants" / "1" / "projects" / "2" / "runs" / "finished")
    in_progress = root / "tenants" / "1" / "projects" / "2" / "runs" / "in-progress"
    in_progress.mkdir(parents=True)
    (in_progress / "ruff-report.json").write_text("[]")
    return root


def backup(tmp_path, scans):
    env_file, calls, subprocess_stub, shutil_stub = _stack_stub(tmp_path)
    original = subprocess_stub.run

    def run(command, **kwargs):
        if command[-2] == "dashboard:/data/scans":
            shutil.copytree(scans, command[-1])
            return type("Result", (), {"returncode": 0})()
        return original(command, **kwargs)

    subprocess_stub.run = run
    destination = tmp_path / "backup.zip"
    code = run_backup(
        project_root=tmp_path, local_env_file=env_file, subprocess_module=subprocess_stub,
        shutil_module=shutil_stub, package_version="test", output=str(destination),
    )
    return code, destination


def restore(tmp_path, archive, **options):
    env_file, calls, subprocess_stub, shutil_stub = _stack_stub(tmp_path)
    code = run_restore(
        str(archive), project_root=tmp_path, local_env_file=env_file,
        subprocess_module=subprocess_stub, shutil_module=shutil_stub, confirmed=True, **options,
    )
    return code, calls


def rewrite(archive, changes):
    """Copy an archive, replacing (bytes) or dropping (None) members."""
    rewritten = archive.with_name("rewritten.zip")
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(rewritten, "w") as target:
        for name in source.namelist():
            if name in changes:
                if changes[name] is not None:
                    target.writestr(name, changes[name])
            else:
                target.writestr(name, source.read(name))
    return rewritten


def test_local_stack_key_derives_the_pinned_public_key(tmp_path):
    env_file = tmp_path / ".env.aegis"
    env_file.write_text(f"AEGIS_EVIDENCE_SIGNING_KEY={DEVELOPMENT_SEED}\n")

    assert evidence_public_key_from_env(env_file) == evidence_public_key()["public_key"]
    assert evidence_public_key_from_env(tmp_path / "missing") is None


def test_backup_records_verified_and_unsigned_runs(tmp_path):
    code, archive = backup(tmp_path, scans_tree(tmp_path / "live-scans"))

    assert code == 0
    with zipfile.ZipFile(archive) as bundle:
        inventory = json.loads(bundle.read("evidence-inventory.json"))
        manifest = json.loads(bundle.read("manifest.json"))
    assert inventory["verified"] == 1 and inventory["failed"] == 0
    assert inventory["runs"][0]["run"] == "tenants/1/projects/2/runs/finished"
    assert inventory["unsigned"] == ["tenants/1/projects/2/runs/in-progress"]
    assert manifest["evidence"] == {"verified_runs": 1, "failed_runs": 0, "unsigned_runs": 1}


def test_restore_verifies_evidence_before_touching_the_database(tmp_path):
    _, archive = backup(tmp_path, scans_tree(tmp_path / "live-scans"))

    code, calls = restore(tmp_path, archive)

    assert code == 0
    assert any("psql" in command for command in calls)


def test_restore_refuses_a_corrupted_artifact(tmp_path):
    _, archive = backup(tmp_path, scans_tree(tmp_path / "live-scans"))
    tampered = rewrite(archive, {"scans/tenants/1/projects/2/runs/finished/report.md": b"decision: forged\n"})

    code, calls = restore(tmp_path, tampered)

    assert code == EXIT_OPERATIONAL_ERROR
    assert not any("psql" in command for command in calls)
    assert restore(tmp_path, tampered, allow_evidence_failures=True)[0] == 0


def test_restore_refuses_a_run_missing_since_backup(tmp_path):
    _, archive = backup(tmp_path, scans_tree(tmp_path / "live-scans"))
    prefix = "scans/tenants/1/projects/2/runs/finished/"
    trimmed = rewrite(archive, {prefix + "report.md": None, prefix + "scan-manifest.json": None})

    code, calls = restore(tmp_path, trimmed)

    assert code == EXIT_OPERATIONAL_ERROR
    assert not any("psql" in command for command in calls)


def test_restore_refuses_the_wrong_public_key(tmp_path):
    _, archive = backup(tmp_path, scans_tree(tmp_path / "live-scans"))

    code, calls = restore(tmp_path, archive, public_key="A" * 43)

    assert code == EXIT_OPERATIONAL_ERROR
    assert not any("psql" in command for command in calls)


def test_restore_requires_a_trust_anchor(tmp_path):
    _, archive = backup(tmp_path, scans_tree(tmp_path / "live-scans"))
    env_file, calls, subprocess_stub, shutil_stub = _stack_stub(tmp_path)
    env_file.write_text("")

    code = run_restore(
        str(archive), project_root=tmp_path, local_env_file=env_file,
        subprocess_module=subprocess_stub, shutil_module=shutil_stub, confirmed=True,
    )

    assert code == EXIT_OPERATIONAL_ERROR
    assert calls == []


def test_legacy_backups_without_an_inventory_are_still_checked(tmp_path):
    archive = tmp_path / "legacy.zip"
    scans = scans_tree(tmp_path / "legacy-scans")
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("database.sql", "SELECT 1;\n")
        for path in scans.rglob("*"):
            if path.is_file():
                bundle.write(path, "scans/" + path.relative_to(scans).as_posix())

    assert restore(tmp_path, archive)[0] == 0
    corrupted = rewrite(archive, {"scans/tenants/1/projects/2/runs/finished/report.md": b"forged\n"})
    assert restore(tmp_path, corrupted)[0] == EXIT_OPERATIONAL_ERROR


@pytest.mark.parametrize("member", ["evidence-inventory.json"])
def test_backup_without_scans_still_writes_an_empty_inventory(tmp_path, member):
    env_file, calls, subprocess_stub, shutil_stub = _stack_stub(tmp_path)
    destination = tmp_path / "empty.zip"

    assert run_backup(
        project_root=tmp_path, local_env_file=env_file, subprocess_module=subprocess_stub,
        shutil_module=shutil_stub, package_version="test", output=str(destination),
    ) == 0
    with zipfile.ZipFile(destination) as bundle:
        assert json.loads(bundle.read(member))["verified"] == 0
