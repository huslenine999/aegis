# Semgrep rule fixtures

Labeled samples for `rules/semgrep_rules.yaml`. A `ruleid: <id>` comment means
the next line must produce exactly that finding; `ok: <id>` means the next line
must not. `tests/test_semgrep_rules.py` enforces both. These files are
intentionally vulnerable and are never executed.
