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

## CodeQL held-out corpus v2 (`codeql-heldout-v2`), 2026-10-22

28 fresh synthetic cases (14 vulnerable, 14 safe twins) in Python (Django,
Flask, FastAPI) and JavaScript (Express): SQL injection (including a
cross-function flow), path traversal, SSRF, unsafe deserialization, code
injection, reflected XSS, open redirect, and cross-function command injection.
None of these cases appear in v1. They were written without reading
`rules/semgrep_rules.yaml`, the corpus SHA-256 (`1881cd3c…`) was recorded
before the first run, and no rules changed afterwards. Do not tune rules
against v2; measure any rule changes on a new corpus.

How it was run:

- CodeQL CLI 2.27.0, official `linux64` bundle (SHA-256 verified against
  `scripts/setup_codeql.sh`), same suites as v1, `--build-mode=none`.
- Semgrep 1.179.0 with `rules/semgrep_rules.yaml` (`b26b5942…`), using the
  same target selection as production scans.
- Command:
  `python scripts/run_codeql_benchmark.py --corpus benchmarks/codeql-heldout-v2.json --codeql-cli <path>/codeql --with-semgrep`

| Detector | Caught (of 14) | False alarms (of 14 safe) |
| --- | ---: | ---: |
| CodeQL, any alert counts | 14 | 2 |
| CodeQL, target classes only | 14 | 0 |
| Aegis Semgrep rules | 7 | 3 |
| Aegis Semgrep, without `javascript-express-tainted-request` | 4 | 0 |
| CodeQL + Semgrep | 14 | 4 |

CodeQL's two false alarms are `js/missing-rate-limiting` on safe Express
routes, as in v1.

`javascript-express-tainted-request` fired on both members of three Express
pairs (path traversal, SSRF, open redirect), so it raised an alert without
telling the vulnerable and safe versions apart. The class-specific Semgrep
rules caught Django f-string SQL, `pickle.loads`, `eval`, and `execSync`
command construction. They do not cover Python path traversal, SSRF,
reflected XSS, or open redirect, Express SQL injection or reflected XSS, or SQL
built with `.format()` in a helper function. Standard scans (no CodeQL) miss
those classes on these fixtures; Deep catches them.

Files:

- `codeql-heldout-v2.2026-10-22.held-out.json`: direct CLI plus Semgrep.
- `codeql-heldout-v2.2026-10-22.isolated-standin.json`: the same corpus through
  the production isolated runner (`run_codeql_scan_isolated`, offline
  container) on the stand-in image described below. CodeQL results are
  identical to the direct run.

## Real-repository inventory (`repositories-v1`), 2026-10-22

Seven public repositories pinned by commit: four training labs with
documented weaknesses (pygoat, VAmPI, NodeGoat, dvpwa) and three maintained
applications (microblog, full-stack-fastapi-template,
node-express-realworld-example-app). All seven scans completed (0 operational
failures), and a second run produced identical alerts. Counts are flagged
(file, rule) pairs, the unit a reviewer triages.

Command:
`python scripts/run_codeql_benchmark.py --repositories --codeql-cli <path>/codeql`

| Repository | Kind | CodeQL pairs | Semgrep pairs |
| --- | --- | ---: | ---: |
| pygoat | lab | 33 | 10 |
| VAmPI | lab | 2 | 0 |
| NodeGoat | lab | 14 | 2 |
| dvpwa | lab | 5 | 3 |
| microblog | app | 4 | 2 |
| full-stack-fastapi-template | app | 8 | 0 |
| node-express-realworld-example-app | app | 1 | 0 |

Triage of the three applications (one reviewer, Claude, 2026-10-22; needs a
second reviewer before it is cited):

| Repository | Detector / rule | Pairs | Verdict |
| --- | --- | ---: | --- |
| microblog | CodeQL `py/reflective-xss` | 2 | False: handlers return dicts that Flask serializes as JSON |
| microblog | CodeQL `py/url-redirection` | 1 | True, low: `next` is checked only for an empty netloc, so `/\evil.example` passes |
| microblog | CodeQL `py/partial-ssrf` | 1 | True, low: user language codes reach the query string of a fixed translator URL |
| microblog | Semgrep `python-rce` | 1 | Not exploitable: `os.system` input is a developer CLI argument |
| microblog | Semgrep `python-weak-hash` | 1 | False: MD5 builds a Gravatar URL, not a security control |
| full-stack-fastapi-template | CodeQL `js/insecure-randomness` | 7 | False: `Math.random` in Playwright test helpers |
| full-stack-fastapi-template | CodeQL `py/jinja2/autoescape-false` | 1 | True, low: HTML emails render user fields without autoescaping |
| node-express-realworld-example-app | CodeQL `js/missing-rate-limiting` | 1 | True, hardening: the login route has no rate limit |

On these applications CodeQL had 4 true and 9 false pairs, and Aegis Semgrep
had 0 true and 2 false. Seven of CodeQL's false pairs come from test code:
Deep scans analyze test directories, while Semgrep skips `tests/` by default.

One documented lab flaw was missed by both detectors: VAmPI's SQL injection
(`models/user_model.py:72`, an f-string passed to `text()`). VAmPI routes
requests through Connexion's OpenAPI mapping, which CodeQL does not model as a
request source, and the Aegis `python-sqli` rule requires a request object.
Ruff `S608`, which runs in every Aegis preset, does flag that line. The labs
are otherwise inventoried, not labeled, so this run gives no recall figure.

## Deep isolation checks, 2026-10-22

`tests/integration/test_codeql_isolation.py` runs adversarial probes inside the
CodeQL image with the exact `docker run` flags Aegis uses for analysis. It
checks that only loopback is up and no IPv4 routes exist, that IPv4, IPv6, and
DNS egress fail, the user and capabilities, `no_new_privs`, a read-only
image, unexpected mounts and the Docker socket, environment leakage (a canary
variable in the Docker client's environment), the 4 GiB memory and 128-process
limits, and whether two concurrent analysis containers can see each other's
files or processes.

Run it on each host that runs Deep scans, after `make codeql-setup`:

```
AEGIS_CODEQL_ISOLATION=1 uv run pytest tests/integration/test_codeql_isolation.py
```

Result on the developer's Mac: both tests passed on 2026-10-22 with the
pinned image
`aegis-codeql@sha256:5e562ed05171ea425b1faa602bbe53c9c6bff525e23bf274534f4e142aeb89e2`
(test file SHA-256 `84c7ba60…`). The first run there failed one assertion, and
the cause was the test, not the container. The Mac's Docker kernel adds idle
tunnel devices (`gre0`, `sit0`, `ip6gre0`, and others) to every network
namespace, and the test had required `lo` to be the only interface listed.
Those devices are down, with no addresses or routes. The test now checks
interfaces that are up and the routing table, adds an IPv6 connection attempt,
and reports every check in one comparison. pytest records only pass or fail,
so this run has no per-probe output file.

Result on a stand-in, before that fix: both tests passed. Docker Hub was
unreachable, so the image was rebuilt to `Dockerfile.codeql`'s recipe from the official Debian
bookworm-slim root filesystem, Python 3.11.15 (python-build-standalone), and
the verified CodeQL 2.27.0 `linux64` bundle. Docker 29.9.1 ran nested on
x86_64 with cgroup v1 and the builtin seccomp profile. Two negative controls
confirmed the probes can fail: without the isolation flags the container
reached the network and DNS, wrote to its image, had no memory limit, and
spawned all 200 processes; with the Docker socket mounted, the mount and
socket checks failed. Details are in
`codeql-isolation.2026-10-22.standin.json`, which the earlier probe version
produced; it lists all interfaces, not just those that are up. After the fix,
the stand-in passed again, and with networking on the test failed as intended
(`eth0` up, two routes, TCP and DNS reachable).

Re-run the test after changes to the CodeQL image, Docker engine, or launch
flags, and on any other host that runs Deep scans. The checks cover the
analysis container only. The Deep worker that starts it still holds database,
signing, and Docker-daemon access (F06).

## CodeQL held-out corpus v3 (`codeql-heldout-v3`), 2026-10-28

Status: **run once on 2026-10-28; no rules changed afterwards.**

`benchmarks/codeql-heldout-v3.json` has 28 cases: 14 vulnerable and 14 safe
twins. Each twin keeps the framework and data source and removes the dangerous
flow with an allowlist lookup, escaping, a parameterized query, a `realpath`
prefix check, or an argument list instead of a shell string.

| Class | Python (aiohttp, Starlette) | JavaScript (Express, Koa) |
|---|---|---|
| Path traversal | `py/path-injection` | `js/path-injection` |
| SSRF | `py/full-ssrf` | `js/request-forgery` |
| Reflected XSS | `py/reflective-xss` | `js/reflected-xss` |
| Open redirect | `py/url-redirection` | `js/server-side-unvalidated-url-redirection` |
| SQL injection | `py/sql-injection` (`.format()` helper, `%` helper) | `js/sql-injection` |
| Command injection | `py/command-line-injection` | `js/command-line-injection` |
| Unsafe deserialization | `py/unsafe-deserialization` | |

SHA-256: `45eab3bc6103e2616fd4e511e38ddd5763cd1ca7351ca5582b2acfb878d34436`

The corpus was written without opening `rules/semgrep_rules.yaml`, the Semgrep
fixtures, `tests/test_semgrep_rules.py` or any earlier corpus. The Semgrep rules
for these classes were written in a separate session that did not read the
corpus.

How it was run:

- CodeQL CLI 2.27.0 through the production isolated runner (offline container,
  `aegis-codeql@sha256:cdb756b8…`, isolation verified), same suites as v1 and v2.
- Semgrep 1.179.0 with `rules/semgrep_rules.yaml` (`cdde3e04…`).
- The `corpus_sha256` in the output matches the SHA-256 above.
- Command:
  `python scripts/run_codeql_benchmark.py --corpus benchmarks/codeql-heldout-v3.json --with-semgrep --output benchmarks/results/codeql-heldout-v3.2026-10-28.held-out.json`

| Detector | Caught (of 14) | False alarms (of 14 safe) |
| --- | ---: | ---: |
| CodeQL, any alert counts | 9 | 2 |
| CodeQL, target classes only | 9 | 0 |
| Aegis Semgrep rules | 13 | 0 |
| CodeQL + Semgrep | 14 | 2 |

CodeQL's two false alarms are `js/missing-rate-limiting` on the safe Express
routes `express_user_lookup-safe` and `express_send_document-safe`, as in v1 and
v2. Counting target classes only, CodeQL + Semgrep has no false alarms.

Misses:

- CodeQL missed five Python cases, all Starlette: SSRF
  (`starlette_proxy-vuln`), reflected XSS (`starlette_greeting-vuln`), open
  redirect (`starlette_login_redirect-vuln`), SQL injection through a `%` helper
  (`starlette_sql_percent_helper-vuln`) and unsafe deserialization
  (`starlette_import_session-vuln`). Semgrep caught all five. Every aiohttp and
  Express/Koa case that CodeQL was expected to catch, it caught.
- Semgrep missed one case: `koa_exit_redirect-vuln`
  (`js/server-side-unvalidated-url-redirection`). CodeQL caught it.
- Semgrep caught `starlette_proxy-vuln` and `starlette_login_redirect-vuln`
  through the generic `python-tainted-request` rule, not a class-specific rule.

This is a single run. No rules changed after it, and the corpus is now used up
for tuning: measure further rule changes on a new corpus.

Files:

- `codeql-heldout-v3.2026-10-28.held-out.json`: isolated runner plus Semgrep.

## Koa context sources (2026-10-28)

`javascript-express-tainted-request` and the Express SQL/XSS rules shared its
sources, which only knew `(req, res)` handlers. They now also treat `ctx.query`,
`ctx.params`, `ctx.request.query`, `ctx.request.body` and `ctx.headers` as
request input inside a handler whose first parameter is named `ctx`. This was
written after reading the v3 miss `koa_exit_redirect-vuln`, so v3 no longer
measures it: re-running v3 catches 14/14 with no false alarms, which is only a
regression check. The labeled fixture `tests/fixtures/semgrep/koa_routes.js`
covers the change. Held-out recall for Koa is unmeasured until a fresh corpus
is written.
