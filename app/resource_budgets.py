"""Shared resource budgets for untrusted scanner and report data.

The scanner handles data produced by tools, repositories, object storage, and
HTTP clients.  Those inputs are not trusted merely because they are handled
inside the application, so every boundary that can accumulate bytes has a
small, explicit budget.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import selectors
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, SupportsIndex, TextIO, cast


class ResourceLimitError(ValueError):
    """Raised when an input or output exceeds its configured resource budget."""


DEFAULT_MAX_SUBPROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_PARSER_INPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_ZIP_ENTRIES = 256
DEFAULT_MAX_ZIP_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_SCANNER_REPORT_BYTES = DEFAULT_MAX_SUBPROCESS_OUTPUT_BYTES
DEFAULT_MAX_SCANNER_FINDINGS = 10_000
DEFAULT_STREAM_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class ResourceBudgets:
    max_subprocess_output_bytes: int
    max_parser_input_bytes: int
    max_response_bytes: int
    max_zip_entries: int
    max_zip_uncompressed_bytes: int
    max_scanner_report_bytes: int
    max_scanner_findings: int
    stream_chunk_bytes: int


def _positive_limit(name: str, default: int) -> int:
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ResourceLimitError(f"{name} must be a positive integer.") from exc
    if value < 1:
        raise ResourceLimitError(f"{name} must be a positive integer.")
    return value


def resource_budgets() -> ResourceBudgets:
    """Read resource limits at the point of use so tests and operators can tune them."""

    return ResourceBudgets(
        max_subprocess_output_bytes=_positive_limit(
            "AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES", DEFAULT_MAX_SUBPROCESS_OUTPUT_BYTES
        ),
        max_parser_input_bytes=_positive_limit(
            "AEGIS_MAX_PARSER_INPUT_BYTES", DEFAULT_MAX_PARSER_INPUT_BYTES
        ),
        max_response_bytes=_positive_limit(
            "AEGIS_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES
        ),
        max_zip_entries=_positive_limit(
            "AEGIS_MAX_ZIP_ENTRIES", DEFAULT_MAX_ZIP_ENTRIES
        ),
        max_zip_uncompressed_bytes=_positive_limit(
            "AEGIS_MAX_ZIP_UNCOMPRESSED_BYTES",
            DEFAULT_MAX_ZIP_UNCOMPRESSED_BYTES,
        ),
        max_scanner_report_bytes=_positive_limit(
            "AEGIS_MAX_SCANNER_REPORT_BYTES", DEFAULT_MAX_SCANNER_REPORT_BYTES
        ),
        max_scanner_findings=_positive_limit(
            "AEGIS_MAX_SCANNER_FINDINGS", DEFAULT_MAX_SCANNER_FINDINGS
        ),
        stream_chunk_bytes=_positive_limit(
            "AEGIS_STREAM_CHUNK_BYTES", DEFAULT_STREAM_CHUNK_BYTES
        ),
    )


class BoundedFindingList(list[dict[str, Any]]):
    """List-like scanner findings collection with count and JSON-size limits."""

    def __init__(
        self,
        values: Iterable[dict[str, Any]] | None = None,
        *,
        max_bytes: int | None = None,
        max_findings: int | None = None,
    ) -> None:
        super().__init__()
        budgets = resource_budgets()
        self._max_bytes = (
            budgets.max_scanner_report_bytes if max_bytes is None else max_bytes
        )
        self._max_findings = (
            budgets.max_scanner_findings if max_findings is None else max_findings
        )
        self._encoded_bytes = 2
        if self._max_bytes < 1 or self._max_findings < 1:
            raise ResourceLimitError("Scanner report limits must be positive.")
        if values is not None:
            self.extend(values)

    @staticmethod
    def _encoded_item(value: dict[str, Any]) -> bytes:
        try:
            return json.dumps(
                value, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ResourceLimitError("Scanner findings must be JSON serializable.") from exc

    def append(self, value: dict[str, Any]) -> None:
        encoded = self._encoded_item(value)
        additional = len(encoded) + (1 if self else 0)
        if len(self) >= self._max_findings:
            raise ResourceLimitError(
                f"Scanner findings exceed the configured limit of {self._max_findings}."
            )
        if self._encoded_bytes + additional > self._max_bytes:
            raise ResourceLimitError(
                "Scanner report exceeds the configured serialized byte limit."
            )
        super().append(value)
        self._encoded_bytes += additional

    def extend(self, values: Iterable[dict[str, Any]]) -> None:
        for value in values:
            self.append(value)

    def insert(self, index: SupportsIndex, value: dict[str, Any]) -> None:
        position = index.__index__()
        if position < 0:
            position = max(0, len(self) + position)
        if position >= len(self):
            self.append(value)
            return
        encoded = self._encoded_item(value)
        if len(self) >= self._max_findings:
            raise ResourceLimitError(
                f"Scanner findings exceed the configured limit of {self._max_findings}."
            )
        if self._encoded_bytes + len(encoded) + 1 > self._max_bytes:
            raise ResourceLimitError(
                "Scanner report exceeds the configured serialized byte limit."
            )
        list.insert(self, position, value)
        self._encoded_bytes += len(encoded) + 1


def bounded_json_bytes(value: Any, *, max_bytes: int | None = None) -> bytes:
    """Serialize JSON and fail before an oversized report reaches disk."""

    budget = (
        resource_budgets().max_scanner_report_bytes
        if max_bytes is None
        else max_bytes
    )
    try:
        content = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise ResourceLimitError("Report value must be JSON serializable.") from exc
    if len(content) > budget:
        raise ResourceLimitError(
            f"Scanner report exceeds the configured serialized byte limit of {budget}."
        )
    return content


def iter_bounded(
    stream: BinaryIO,
    limit: int,
    *,
    chunk_size: int | None = None,
) -> Iterable[bytes]:
    """Yield bytes from *stream* while enforcing an actual-read byte limit."""

    if limit < 1:
        raise ResourceLimitError("Resource limits must be positive.")
    read_size = (
        resource_budgets().stream_chunk_bytes if chunk_size is None else chunk_size
    )
    if read_size < 1:
        raise ResourceLimitError("Stream chunk size must be positive.")
    total = 0
    while True:
        requested = min(read_size, limit - total + 1)
        try:
            chunk = stream.read(requested)
        except TypeError:
            # A few urllib/test stream adapters expose read() without a size
            # parameter.  The byte-count check below still fails closed after
            # that adapter returns its complete chunk.
            chunk = stream.read()
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            total += len(chunk)
            if total > limit:
                raise ResourceLimitError(
                    f"Stream exceeds the configured limit of {limit} bytes."
                )
            yield chunk
            return
        if not chunk:
            return
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if total > limit:
            raise ResourceLimitError(
                f"Stream exceeds the configured limit of {limit} bytes."
            )
        yield chunk


def read_bounded(
    stream: BinaryIO,
    limit: int,
    *,
    chunk_size: int | None = None,
) -> bytes:
    """Read a bounded stream into memory for deliberately small parser inputs."""

    return b"".join(iter_bounded(stream, limit, chunk_size=chunk_size))


def iter_file_bytes(
    path: Path,
    *,
    max_bytes: int | None = None,
    chunk_size: int | None = None,
) -> Iterable[bytes]:
    """Stream a regular file with both a preflight and an actual-read check."""

    budget = (
        resource_budgets().max_response_bytes if max_bytes is None else max_bytes
    )
    try:
        if path.stat().st_size > budget:
            raise ResourceLimitError(
                f"File exceeds the configured limit of {budget} bytes."
            )
    except FileNotFoundError:
        raise
    with path.open("rb") as stream:
        yield from iter_bounded(stream, budget, chunk_size=chunk_size)


def load_bounded_json(path: Path, *, max_bytes: int | None = None):
    """Load JSON only after bounding the encoded input size."""

    budget = (
        resource_budgets().max_parser_input_bytes
        if max_bytes is None
        else max_bytes
    )
    with path.open("rb") as stream:
        content = read_bounded(stream, budget)
    return json.loads(content.decode("utf-8"))


def read_bounded_text(
    path: Path,
    *,
    max_bytes: int | None = None,
    errors: str = "strict",
) -> str:
    """Read a bounded text file for manifest, template, or source parsing."""

    budget = (
        resource_budgets().max_parser_input_bytes
        if max_bytes is None
        else max_bytes
    )
    with path.open("rb") as stream:
        content = read_bounded(stream, budget)
    return content.decode("utf-8", errors=errors)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _write_output(sink: TextIO | BinaryIO | None, data: bytes) -> None:
    if sink is None:
        return
    target = cast(Any, sink)
    try:
        target.write(data)
    except TypeError:
        target.write(data.decode("utf-8", errors="replace"))


def _run_bounded_subprocess_threaded(
    process: subprocess.Popen[bytes],
    command: list[str],
    *,
    budget: int,
    stdout_sink: TextIO | BinaryIO | None,
    timeout: int | float | None,
    on_output: Callable[[bytes], None] | None,
    check_callback: Callable[[], None] | None,
) -> subprocess.CompletedProcess[bytes]:
    """Drain a subprocess pipe without relying on Windows ``select()`` support."""
    assert process.stdout is not None
    stdout_stream = process.stdout
    output_queue: queue.Queue[bytes | BaseException | None] = queue.Queue(maxsize=1)
    stop_reader = threading.Event()
    read_size = min(resource_budgets().stream_chunk_bytes, budget + 1)

    def enqueue(item: bytes | BaseException | None) -> None:
        while not stop_reader.is_set():
            try:
                output_queue.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def read_stdout() -> None:
        try:
            while not stop_reader.is_set():
                data = stdout_stream.read(read_size)
                if not data:
                    break
                enqueue(data)
        except BaseException as exc:
            enqueue(exc)
        finally:
            enqueue(None)

    reader = threading.Thread(target=read_stdout, name="aegis-scanner-stdout", daemon=True)
    reader.start()
    started = time.monotonic()
    total = 0
    try:
        while True:
            if check_callback is not None:
                check_callback()
            if timeout is not None and time.monotonic() - started >= timeout:
                _terminate_process(process)
                raise subprocess.TimeoutExpired(command, timeout)
            wait_for = 0.25
            if timeout is not None:
                wait_for = min(
                    wait_for,
                    max(0.01, timeout - (time.monotonic() - started)),
                )
            try:
                data = output_queue.get(timeout=wait_for)
            except queue.Empty:
                continue
            if data is None:
                break
            if isinstance(data, BaseException):
                raise data
            total += len(data)
            if total > budget:
                _terminate_process(process)
                raise ResourceLimitError(
                    f"Subprocess output exceeds the configured limit of {budget} bytes."
                )
            _write_output(stdout_sink, data)
            if on_output is not None:
                on_output(data)
        return_code = process.wait(timeout=1)
        return subprocess.CompletedProcess(command, return_code)
    except BaseException:
        _terminate_process(process)
        raise
    finally:
        stop_reader.set()
        try:
            process.stdout.close()
        except OSError:
            pass
        reader.join(timeout=1)


def run_bounded_subprocess(
    command: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    stdout_sink: TextIO | BinaryIO | None = None,
    timeout: int | float | None = None,
    max_output_bytes: int | None = None,
    on_output: Callable[[bytes], None] | None = None,
    check_callback: Callable[[], None] | None = None,
    preexec_fn: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a command while draining and bounding its stdout.

    Stderr remains redirected to the null device because scanner diagnostics
    are not part of evidence.  Stdout is drained in bounded chunks so a noisy
    tool cannot fill a pipe or grow an in-memory capture without limit.
    """

    budget = (
        resource_budgets().max_subprocess_output_bytes
        if max_output_bytes is None
        else max_output_bytes
    )
    if budget < 1:
        raise ResourceLimitError("Resource limits must be positive.")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=False,
        start_new_session=os.name != "nt",
        preexec_fn=preexec_fn if os.name != "nt" else None,
    )
    assert process.stdout is not None
    if os.name == "nt":
        return _run_bounded_subprocess_threaded(
            process,
            command,
            budget=budget,
            stdout_sink=stdout_sink,
            timeout=timeout,
            on_output=on_output,
            check_callback=check_callback,
        )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    started = time.monotonic()
    total = 0
    try:
        while selector.get_map():
            if check_callback is not None:
                check_callback()
            if timeout is not None and time.monotonic() - started >= timeout:
                _terminate_process(process)
                raise subprocess.TimeoutExpired(command, timeout)
            wait_for = 0.25
            if timeout is not None:
                wait_for = min(wait_for, max(0.01, timeout - (time.monotonic() - started)))
            events = selector.select(wait_for)
            if not events:
                if process.poll() is not None:
                    # A closed process will eventually make the pipe readable;
                    # retain the selector until EOF to avoid dropping bytes.
                    continue
                continue
            for key, _ in events:
                stream = cast(BinaryIO, key.fileobj)
                data = stream.read(
                    min(resource_budgets().stream_chunk_bytes, budget - total + 1)
                )
                if not data:
                    selector.unregister(stream)
                    continue
                total += len(data)
                if total > budget:
                    _terminate_process(process)
                    raise ResourceLimitError(
                        f"Subprocess output exceeds the configured limit of {budget} bytes."
                    )
                _write_output(stdout_sink, data)
                if on_output is not None:
                    on_output(data)
        return_code = process.wait(timeout=1)
        return subprocess.CompletedProcess(command, return_code)
    except BaseException:
        _terminate_process(process)
        raise
    finally:
        selector.close()
        try:
            process.stdout.close()
        except OSError:
            pass


def run_bounded_subprocess_to_file(
    command: list[str],
    output_path: str | Path,
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | float | None = None,
    max_output_bytes: int | None = None,
    on_output: Callable[[bytes], None] | None = None,
    check_callback: Callable[[], None] | None = None,
    accepted_return_codes: set[int] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a POSIX file-writing scanner through a bounded, atomic output sink.

    The command must contain ``str(output_path)`` as its output destination.
    That argument is replaced with a sibling temporary path.  The temporary
    file is monitored while the process runs and is atomically promoted only
    after it remains within the configured byte budget.  Callers that need
    portable enforcement must use :func:`run_bounded_subprocess_stdout_to_file`.
    """
    target = Path(output_path)
    budget = (
        resource_budgets().max_subprocess_output_bytes
        if max_output_bytes is None
        else max_output_bytes
    )
    if budget < 1:
        raise ResourceLimitError("Resource limits must be positive.")
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ResourceLimitError("Scanner output must be a regular file.")
    target_text = str(target)
    if target_text not in command:
        raise ValueError("Bounded file output path is missing from the command.")
    if os.name == "nt":
        raise ResourceLimitError(
            "Direct file-writing subprocess output is not safely bounded on this "
            "platform; use the stdout transport instead."
        )
    try:
        import resource
    except ImportError as exc:
        raise ResourceLimitError(
            "Direct file-writing subprocess output requires POSIX file-size limits; "
            "use the stdout transport instead."
        ) from exc
    if not hasattr(resource, "RLIMIT_FSIZE"):
        raise ResourceLimitError(
            "Direct file-writing subprocess output requires RLIMIT_FSIZE; "
            "use the stdout transport instead."
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    bounded_command = [
        str(temporary) if item == target_text else item for item in command
    ]

    def check_file_output() -> None:
        if temporary.is_symlink() or (temporary.exists() and not temporary.is_file()):
            raise ResourceLimitError("Scanner output must be a regular file.")
        try:
            size = temporary.stat().st_size
        except FileNotFoundError:
            return
        if size > budget:
            raise ResourceLimitError(
                f"Scanner file output exceeds the configured limit of {budget} bytes."
            )

    def check() -> None:
        check_file_output()
        if check_callback is not None:
            check_callback()

    def limit_file_size() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (budget, budget))

    try:
        completed = run_bounded_subprocess(
            bounded_command,
            cwd=cwd,
            env=env,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
            on_output=on_output,
            check_callback=check,
            preexec_fn=limit_file_size,
        )
        check_file_output()
        accepted = {0} if accepted_return_codes is None else accepted_return_codes
        if completed.returncode in accepted and temporary.exists():
            os.replace(temporary, target)
        return subprocess.CompletedProcess(command, completed.returncode)
    finally:
        temporary.unlink(missing_ok=True)


def run_bounded_subprocess_stdout_to_file(
    command: list[str],
    output_path: str | Path,
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | float | None = None,
    max_output_bytes: int | None = None,
    on_output: Callable[[bytes], None] | None = None,
    check_callback: Callable[[], None] | None = None,
    accepted_return_codes: set[int] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Capture bounded stdout into an atomically promoted report file.

    The child never receives a report path.  Its output crosses the bounded
    stdout pipe, while the parent owns the temporary file and therefore the
    only filesystem write.  This is the portable transport for scanners whose
    report format can be emitted to stdout.
    """
    target = Path(output_path)
    budget = (
        resource_budgets().max_subprocess_output_bytes
        if max_output_bytes is None
        else max_output_bytes
    )
    if budget < 1:
        raise ResourceLimitError("Resource limits must be positive.")
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ResourceLimitError("Scanner output must be a regular file.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")

    try:
        with temporary.open("xb") as sink:
            completed = run_bounded_subprocess(
                command,
                cwd=cwd,
                env=env,
                stdout_sink=sink,
                timeout=timeout,
                max_output_bytes=max_output_bytes,
                on_output=on_output,
                check_callback=check_callback,
            )
        if temporary.is_symlink() or not temporary.is_file():
            raise ResourceLimitError("Scanner output must be a regular file.")
        if temporary.stat().st_size > budget:
            raise ResourceLimitError(
                f"Scanner stdout exceeds the configured limit of {budget} bytes."
            )
        accepted = {0} if accepted_return_codes is None else accepted_return_codes
        if completed.returncode in accepted:
            os.replace(temporary, target)
        return subprocess.CompletedProcess(command, completed.returncode)
    finally:
        temporary.unlink(missing_ok=True)
