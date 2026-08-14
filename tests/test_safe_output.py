import json
import os

import pytest

from app.config import load_advisory_config, load_config
from app.safe_output import SafeOutputError, SafeOutputRoot


def test_target_config_is_advisory_only_but_explicit_config_is_trusted(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    config_path = target / "aegis.yml"
    config_path.write_text(
        "scan:\n"
        "  no_docker: true\n"
        "  fail_on: critical\n"
        "  output_dir: ../escape\n"
        "advisory:\n"
        "  owner: security-team\n"
    )

    assert load_config(target) == {}
    assert load_advisory_config(target) == {
        "_config_path": str(config_path.resolve()),
        "advisory": {"owner": "security-team"},
    }
    trusted = load_config(target, explicit_path=config_path)
    assert trusted["scan"]["no_docker"] is True
    assert trusted["scan"]["output_dir"] == "../escape"


def test_safe_output_root_rejects_escape_symlinks_and_special_files(tmp_path):
    output = SafeOutputRoot(tmp_path / "reports")
    output.write_json("nested/report.json", {"status": "ok"})
    output.write_json_path(output.root / "absolute.json", {"status": "ok"})
    assert json.loads((output.root / "nested/report.json").read_text()) == {"status": "ok"}
    assert json.loads((output.root / "absolute.json").read_text()) == {"status": "ok"}

    outside = tmp_path / "outside.txt"
    outside.write_text("must remain unchanged")
    (output.root / "escaped.txt").symlink_to(outside)
    with pytest.raises(SafeOutputError, match="symbolic links"):
        output.write_text("escaped.txt", "attacker-controlled")
    assert outside.read_text() == "must remain unchanged"

    with pytest.raises(SafeOutputError, match="relative"):
        output.write_text("../escape.txt", "nope")

    fifo = output.root / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(SafeOutputError, match="regular files"):
        output.write_text("pipe", "nope")
