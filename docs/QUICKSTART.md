# Aegis quick start

## Scanner only

Install the command-line scanner in an isolated environment:

```bash
pipx install aegis-security-console
aegis scan . --fast
```

## Complete local stack

Clone the repository, then run:

```bash
aegis start
```

This creates `.env.aegis`, starts PostgreSQL, Redis, the worker, dashboard, and
proxy, then opens the first-run wizard at `http://localhost`.

Common lifecycle commands:

```bash
aegis logs --follow
aegis backup
aegis stop
aegis upgrade
```

Open `/projects` to create a project or connect GitHub. Open `/admin` for users,
tokens, diagnostics, audit events, and recent request logs.
