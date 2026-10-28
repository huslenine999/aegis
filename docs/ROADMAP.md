# Aegis roadmap — 2026-10-28

North star: a release gate a small team can trust. It never says ALLOWED when it should not,
and it explains every decision in plain words.

Three tracks share the repo today: the scanner/gate, the self-hosted workbench, and the BAC
thesis lab. The plan makes the gate true first, ships the thesis on time, then makes the whole
thing easy for a stranger to pick up.

## Phase 0 — Make the claims match reality (about 1 week)

1. Close the `tests/` bypass: scan test folders, block by default, allow non-blocking test roots
   only through trusted Aegis config with a named approver. Add the case to
   `tests/test_scanner_evasion.py`.
2. Fix the install path. PyPI serves 2.4.0 (July); the README describes 2.5.0 and later. Publish
   the current release, or point the README at a source install until it is published.
3. Fix the v3 README status line that says no rules changed afterwards.

Done when: the evasion test covers `tests/`, `pipx install` gives the version the README
describes, and every number in the README traces to a results file.

## Phase 1 — Detection you can defend (2–4 weeks)

1. Fix the rule defects in `claude/scanner-review-2026-10-28.md`, starting with Express/Koa
   named handlers and controller methods, XSS through variables, and the wrong sanitizers.
2. Add `aegis-stress-v1.json` to `benchmarks/` as a regression set (not a score).
3. Build v4 from real vulnerable code: the pre-fix version of published CVE fixes as the
   vulnerable case, the fixed version as the safe twin, picked by someone who has not read the
   rules. Freeze it before any rule change.
4. Measure false alarms on real repositories: re-run the pinned `repositories-v1` set with the
   new rules and triage every ERROR finding. False alarms that block releases are what make
   teams uninstall a gate.
5. Publish a coverage card: per language and bug class, what Standard and Deep catch on v4,
   plus known blind spots.
6. Scope suppressions to a finding fingerprint, not a whole file and rule.

Done when: v4 has a frozen result for Standard and Deep, the coverage card is in the README,
and real-repo false alarms are counted and explained.

## Phase 2 — Thesis (parallel track; the professor's deadlines set its dates)

1. Confirm the research question with the professor and freeze the BAC protocol.
2. Run the final evaluation once, archive the artifacts, fill `RESULTS_PENDING` and
   `CONCLUSION_PENDING`.
3. Tag the exact commit the thesis used, so the results stay reproducible after product work
   continues.
4. After submission, move the BAC lab out of the product path (its own package or a clearly
   separate `research/` area).

If the thesis deadline is close, this track comes before Phase 1.

## Phase 3 — Useful to someone who has never met you (3–4 weeks)

1. Five-minute first run: `pipx install` → `aegis scan .` → a readable verdict. Measure it by
   watching someone new try it.
2. A public demo repository with planted bugs and a pull request that Aegis blocks, linked from
   the README.
3. Shorter README: what Aegis is, a quick start, the coverage card, then links. Group docs into
   Use, Operate, Trust (security documents) and Research.
4. Let teams that already run CodeQL in GitHub code scanning feed that SARIF into the Aegis
   policy, so they get Deep-level coverage without provisioning CodeQL themselves.
5. Two or three real pilot teams on the GitHub Action, with notes on every place they got stuck.

Done when: a stranger reaches a first verdict without help, and at least one outside team has
used the gate on real pull requests.

## Later, only when someone asks

- The remaining F06 work (standard scans sandboxed, unprivileged supervisor, seccomp/gVisor).
- Splitting `app/database.py` and `app/worker.py`.
- Compliance mapping and fleet-level risk rollup.
- The taint analysis tool stays a separate project until Phase 1 is done.

## Stop doing for now

- New frameworks or languages before the existing ones are measured on v4.
- New enterprise features (identity, storage, notifications) without a user asking.
- Tuning rules against a corpus and then reporting that corpus as held-out.
