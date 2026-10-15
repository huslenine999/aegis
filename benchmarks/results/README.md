# Benchmark results

## CodeQL held-out corpus (`codeql-heldout-v1`), 2026-10-16

Eight synthetic source/sink pairs (four vulnerable, four safe counterparts) in
Python and JavaScript. Neither scanner was tuned against these cases before the
held-out run. The corpus measures query behavior on small fixtures; it says
nothing about accuracy on real repositories.

How it was run:

- CodeQL CLI 2.27.0, official `linux-arm64` bundle (SHA-256 verified against
  `scripts/setup_codeql.sh`), the `python-security-extended` and
  `javascript-security-extended` suites, `--build-mode=none`.
- Run with `--codeql-cli` (the CLI directly, not the isolated container).
  Isolation protects the host from hostile repositories; it does not change
  which queries fire on a fixed corpus.
- Semgrep 1.173.0 with `rules/semgrep_rules.yaml`. Each report records the
  rules file's SHA-256.
- Command:
  `python scripts/run_codeql_benchmark.py --codeql-cli <path>/codeql --with-semgrep`

| Detector | Run | Caught (of 4) | False alarms (of 4 safe) |
| --- | --- | ---: | ---: |
| CodeQL, any alert counts | held-out | 4 | 1 |
| CodeQL, target classes only | held-out | 4 | 0 |
| Aegis Semgrep rules | **held-out** | **1** | 0 |
| Aegis Semgrep rules | after rule fixes (not held-out) | 4 | 0 |
| CodeQL + Semgrep | after rule fixes (not held-out) | 4 | 1 |

CodeQL's one false alarm is `js/missing-rate-limiting` on the safe
`execFile` route: a real `security-extended` query, but not the
command-injection class that case tests. Under strict scoring any alert on a
safe case counts, so the run reports `passed: false`.

The held-out Semgrep result exposed three rule defects, all fixed afterwards
with dedicated fixtures in `tests/fixtures/semgrep/`:

1. `python-rce` matched `shell=True` only as the last argument, so
   `subprocess.run(cmd, shell=True, capture_output=True)` was missed.
2. `python-sqli` treated only FastAPI-style request objects as untrusted, so
   Flask `request.args` and Django `request.GET` were missed.
3. `javascript-command-injection` missed `const { exec } = require('child_process')`
   when no namespace object was also in scope. The original fixture hid this
   because the same file also imported the module as an object.

Because the fixes were made after seeing these cases, the "after rule fixes"
row is a regression check, not an independent estimate. A fresh held-out
corpus is needed to measure the fixed rules. SARIF digests differ between runs
because SARIF output includes run timestamps.

Files:

- `codeql-heldout-v1.2026-10-16.held-out.json`: Semgrep rules as committed
  in `44e65d1`.
- `codeql-heldout-v1.2026-10-16.after-rule-fixes.json`: after the three fixes.
