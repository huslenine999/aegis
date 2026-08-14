"""Shared resource budgets for untrusted scanner and report data.

The scanner handles data produced by tools, repositories, object storage, and
HTTP clients.  Those inputs are not trusted merely because they are handled
inside the application, so every boundary that can accumulate bytes has a
small, explicit budget.
"""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, TextIO, cast


class ResourceLimitError(ValueError):
    """Raised when an input or output exceeds its configured resource budget."""


DEFAULT_MAX_SUBPROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_PARSER_INPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_ZIP_ENTRIES = 256
DEFAULT_MAX_ZIP_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
DEFAULT_STREAM_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class ResourceBudgets:
    max_subprocess_output_bytes: int
    max_parser_input_bytes: int
    max_response_bytes: int
    max_zip_entries: int
    max_zip_uncompressed_bytes: int
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
        stream_chunk_bytes=_positive_limit(
            "AEGIS_STREAM_CHUNK_BYTES", DEFAULT_STREAM_CHUNK_BYTES
        ),
    )


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
        process.terminate()
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        try:
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
    )
    assert process.stdout is not None
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
