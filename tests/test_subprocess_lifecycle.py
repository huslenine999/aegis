import io
import os
import signal
import subprocess
import sys
import time

import pytest

from app.resource_budgets import run_bounded_subprocess


@pytest.mark.skipif(os.name == "nt", reason="POSIX pipe and process-group lifecycle")
def test_partial_output_does_not_delay_scanner_timeout():
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_subprocess(
            [sys.executable, "-c", "import sys,time; sys.stdout.write('x'); sys.stdout.flush(); time.sleep(2)"],
            timeout=0.2,
        )
    assert time.monotonic() - started < 1.5


@pytest.mark.skipif(os.name == "nt", reason="POSIX pipe and process-group lifecycle")
def test_partial_output_does_not_delay_scanner_cancellation():
    started = time.monotonic()
    output = io.BytesIO()

    def check_cancelled():
        if time.monotonic() - started >= 0.2:
            raise RuntimeError("scan cancelled")

    with pytest.raises(RuntimeError, match="scan cancelled"):
        run_bounded_subprocess(
            [sys.executable, "-c", "import sys,time; sys.stdout.write('x'); sys.stdout.flush(); time.sleep(2)"],
            timeout=3,
            stdout_sink=output,
            check_callback=check_cancelled,
        )
    assert time.monotonic() - started < 1.5
    assert output.getvalue() == b"x"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group cleanup")
def test_timeout_kills_descendants_after_parent_exit(tmp_path):
    marker = tmp_path / "descendant-finished"
    pid_file = tmp_path / "descendant.pid"
    child_code = (
        "import os,signal,sys,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "Path(sys.argv[1]).write_text(str(os.getpid())); "
        "time.sleep(1.5); Path(sys.argv[2]).write_text('survived')"
    )
    parent_code = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2], sys.argv[3]])"
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_bounded_subprocess(
                [sys.executable, "-c", parent_code, child_code, str(pid_file), str(marker)],
                timeout=0.3,
            )
        assert pid_file.exists(), "descendant must start before the timeout"
        time.sleep(1.5)
        assert not marker.exists(), "the cancelled process group still ran a descendant"
    finally:
        if pid_file.exists():
            try:
                os.killpg(os.getpgid(int(pid_file.read_text())), signal.SIGKILL)
            except ProcessLookupError:
                pass
