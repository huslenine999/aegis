# Scanner sandbox design (F06, Phase 7)

Status: approved 2026-10-28 (option A, deep-worker only) and implemented. Differences from the plan are listed at the end.

## Problem

CodeQL already runs in a throwaway container (`_docker_base` in
`app/codeql_scanner.py`, probes in `tests/integration/test_codeql_isolation.py`).
Ruff, Semgrep and detect-secrets still run as plain subprocesses of the worker:

- Worker: `app/worker.py` (`build_ruff_command`, the Semgrep command, the
  `detect_secrets` command).
- CLI: `app/cli_runner.py` (same three calls).

A repository that exploits one of those tools runs code with the worker's
database login, network access and view of every in-flight source tree.

## Design

### Sandbox flags

Reuse `_docker_base` unchanged: no network, read-only root, all capabilities
dropped, `no-new-privileges`, 128 PIDs, 4 GB memory, 2 CPUs, UID 10001, tmpfs
`/work` and `/tmp`, no host mounts, `--pull=never`, digest-pinned image.
Move it (and `_remove_container`) to a small shared module only if importing
from `codeql_scanner` proves awkward; otherwise import it as is.

### Image

`Dockerfile.scanner`, built locally by `make scanner-setup`
(`scripts/setup_scanner.sh`), same base image digest as `Dockerfile.codeql`.
It installs Ruff, Semgrep and detect-secrets from a hash-pinned requirements
file exported from `uv.lock` (`--require-hashes`), so the versions match the
locked ones. The script writes `AEGIS_SCANNER_IMAGE=<repo>@sha256:...` to
`.env.aegis`, like `setup_codeql.sh` does for CodeQL. The image holds no rules
and no Aegis code.

### Data in, data out

One container per scanner (same shape as one container per CodeQL language):

- In: a tar on stdin, built by the existing `_source_tar` (skips symlinks and
  ignored dirs). For Semgrep the tar also carries `rules/` from
  `PROJECT_ROOT` (trusted, never from the target), so rules changes need no
  image rebuild.
- Out: the scanner's JSON on stdout, written with
  `run_bounded_subprocess_stdout_to_file`. Downstream parsing, `mark_tool`,
  `semgrep_coverage_gaps` and report normalisation stay as they are.
- Paths: scanners run with cwd `/work/source`; the report's `/work/source`
  prefix is rewritten to the real `target_path` before the existing
  `normalize_scan_report_paths` step.

Commands are the existing builders (`build_ruff_command`,
`add_semgrep_excludes`, `DETECT_SECRETS_TRUSTED_FLAGS`) with container paths,
so repository-config protections (`--isolated`, `--disable-nosem`, no
allowlist pragmas) carry over.

### Semgrep offline

`--metrics off --disable-version-check`, `--config /work/rules/semgrep_rules.yaml`
only, `SEMGREP_SETTINGS_FILE` and `SEMGREP_LOG_FILE` under `/tmp`. Network is
off, so any remote rule or registry fetch fails instead of silently
succeeding.

### Opt-in and fail closed

New setting `AEGIS_SANDBOX_SCANNERS` (default off), read from operator
environment only, never repository config.

- Off: current behaviour, including `aegis scan` without Docker.
- On, runtime or image missing or not digest-pinned: each of the three tools is
  marked `failed` with a clear detail. That already produces ERROR, never
  ALLOWED, under strict gates. No fallback to unsandboxed.
- On and working: the tool record carries the image digest and
  `isolation: verified`, as the CodeQL report does.

### Limits

- Timeout per container: existing `AEGIS_SCANNER_TIMEOUT_SECONDS` (secrets keeps
  its 120 s cap).
- Output: existing `AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES` via the bounded runner;
  exceeding it fails the tool.
- Source size: already bounded by workspace admission before scanning.
- Incomplete coverage: timeout, OOM-kill, bad JSON, or Semgrep coverage gaps
  mark the tool `failed`, same as today.
- Containers are removed in `finally`, including on timeout.

### Where Docker lives (decision needed)

The default `worker` has no Docker socket. Only `deep-worker` mounts it, and
the socket is effectively host root. Options:

A. **Sandbox only on `deep-worker`** (recommended). Operators who enable it run
   scans on that worker. The default worker keeps its current, smaller
   privileges and unsandboxed scanners. Smallest change, no new socket exposure.
B. **Give the default worker the socket.** Every scan is sandboxed, but the
   worker, which parses hostile output, can then reach the Docker daemon. This
   trades a scanner-exploit risk for a worse worker-compromise risk.
C. **Job broker service** that owns the socket and runs containers on request.
   Best isolation, much larger build, and `THREAT_MODEL.md` already names it as
   the long-term fix. Out of scope here.

### Tests

New `tests/integration/test_scanner_isolation.py`, opt-in with
`AEGIS_SCANNER_ISOLATION=1`, like the CodeQL one:

- Reuse the CodeQL probe (move `PROBE` and the assertions into a shared helper
  parametrised by image and the image path to try writing) and run it in the
  scanner image with the exact flags: no egress, no capabilities, read-only
  image, no leaked env, PID and memory limits.
- Negative controls: the same probe run without `--network=none` or without
  `--read-only` must show egress or a writable image, proving the probe can
  fail.
- Functional: a booby-trapped fixture (Semgrep rule fetch attempt, a file
  trying to read `/proc/1/environ` or reach a canary host) yields findings and
  no escape.
- Unit tests (no Docker): fail-closed when enabled with no image or Docker,
  command construction, path rewrite, flag off leaves commands unchanged.

### After approval

1. Image and setup script, `make scanner-setup`.
2. Sandboxed runner and worker integration, one commit.
3. CLI integration, one commit.
4. Tests, then run the isolation tests on this Mac.
5. Update `docs/THREAT_MODEL.md` and the F06 row in
   `docs/research/CAPSTONE_REVIEW.md` (residual: the supervisor still holds the
   socket and database login).

## Residual risk after this change

- The Docker-capable worker is still a privileged supervisor. A flaw in its
  Python code crosses the boundary. Option C removes that.
- Container escape (kernel or runtime bug) is not addressed; gVisor or a
  seccomp profile on the target host would harden it.
- A compromised worker can still read the source it is scanning and misreport
  in-flight runs.

## As built (differences from the plan)

- The scan target is extracted at its own path inside the container (a tmpfs
  mount at that path), and Semgrep rules at their own host path with the
  command run from the project root. Reports, paths and Semgrep check IDs are
  then identical to an unsandboxed run, so no path rewriting is needed and
  findings keep their fingerprints.
- No staging tar inside the container: stdin streams into `tar -xf - -C /`.
- Docker socket location comes from `AEGIS_CODEQL_DOCKER_HOST` (the CodeQL
  setting). On Docker Desktop for Mac set it to the context's socket, for
  example the value of `docker context inspect --format '{{.Endpoints.docker.Host}}'`.
- The image installs the hash-pinned `requirements.txt` export, so it carries
  the app's dependencies as well as the three scanners.
- In Compose, the `deep-worker` only consumes the `deep` queue, so sandboxing
  there covers Deep scans. Standard scans stay unsandboxed unless a worker with
  the socket is added. The CLI sandboxes every scan when the flag is set.
- Completed tools record `detail: "sandboxed"`. The image digest is not yet
  recorded per tool.
- A worker started with the flag but no usable image fails each scan at run
  time instead of at startup.
