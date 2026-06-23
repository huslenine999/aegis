import os
import sys
import json
from pathlib import Path
from unittest.mock import patch

# Ensure we can import app.cli
sys.path.append(str(Path(__file__).resolve().parent.parent))
sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))

from app.cli import install_hook, uninstall_hook, execute_scan


def fake_scanner_command(command, *, stdout=None, timeout=120, label="Scanner"):
    if "ruff" in command:
        output_path = Path(command[command.index("-o") + 1])
        target_path = Path(command[command.index(str(output_path)) + 1])
        findings = []
        if target_path.read_text(errors="ignore").find("eval(") >= 0:
            findings.append({
                "code": "S307",
                "filename": str(target_path),
                "location": {"row": 1, "column": 1},
                "message": "Use of possibly insecure function; consider using ast.literal_eval",
            })
        output_path.write_text(json.dumps(findings))
    elif stdout is not None:
        stdout.write('{"results": {}}')
    return 0

def test_install_uninstall_hook(tmp_path, monkeypatch):
    # Setup mock git repository directory structure
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    
    # Change working directory to tmp_path so .git is detected locally
    monkeypatch.chdir(tmp_path)
    
    # Install the hook
    assert install_hook() == 0
    
    pre_push_hook = git_dir / "hooks" / "pre-push"
    assert pre_push_hook.exists()
    
    # Check that hook has execution permissions
    assert os.access(pre_push_hook, os.X_OK)
    
    # Uninstall the hook
    assert uninstall_hook() == 0
    assert not pre_push_hook.exists()

def test_execute_scan_safe_target(tmp_path, monkeypatch):
    # Setup a safe python target file
    target_file = tmp_path / "safe.py"
    target_file.write_text("def add(a, b):\n    return a + b\n")
    
    monkeypatch.chdir(tmp_path)
    
    # Run scan on safe.py
    # Since there are no vulnerability issues in safe.py, it should exit with 0 (ALLOWED)
    # We mock query_osv_vulnerabilities and other docker checks to be fast and deterministic
    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command):
        assert execute_scan(str(target_file), use_docker=False, tool_timeout=5) == 0

def test_execute_scan_unsafe_target(tmp_path, monkeypatch):
    # Setup an unsafe python target file with eval payload (which Semgrep/Bandit/YARA/ClamAV fallbacks will flag)
    target_file = tmp_path / "unsafe.py"
    target_file.write_text("eval(request.args.get('code'))\n")
    
    monkeypatch.chdir(tmp_path)
    
    # Run scan on unsafe.py
    # Since there are vulnerabilities in unsafe.py, it should exit with 1 (BLOCKED)
    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command):
        assert execute_scan(str(target_file), use_docker=False, tool_timeout=5) == 1

def test_print_ascii_report(capsys):
    from app.cli import print_ascii_report
    results = [
        {"tool": "Ruff (SAST)", "status": "PASS", "total_issues": 0, "blocking_issues": 0},
        {"tool": "Secrets Scanner", "status": "FAIL", "total_issues": 3, "blocking_issues": 3}
    ]
    print_ascii_report(results, "BLOCKED", "Blocking issues found by: Secrets Scanner", 60.0)
    captured = capsys.readouterr()
    
    # Assert ASCII borders and headers exist
    assert "╔════════════" in captured.out
    assert "A E G I S   S E C U R I T Y" in captured.out
    assert "Ruff (SAST)" in captured.out
    assert "Secrets Scanner" in captured.out
    assert "VERDICT:" in captured.out and "DEPLOYMENT BLOCKED" in captured.out
    assert "REASON:" in captured.out and "Blocking issues found by: Secrets Scanner" in captured.out
