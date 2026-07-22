# Aegis quick start

## Scanner only

Install the command-line scanner in an isolated environment:

```bash
pipx install "aegis-security-console[scanner]"
aegis demo
aegis scan .
```

If the package has not reached PyPI yet, install the current repository
revision with
`pipx install "git+https://github.com/huslenine999/aegis.git#egg=aegis-security-console[scanner]"`.

## Complete local stack

The complete stack requires the deployment files from a source checkout:

```bash
git clone https://github.com/huslenine999/aegis.git
cd aegis
python3 -m venv venv
./venv/bin/python -m pip install -e ".[dev,scanner]"
./venv/bin/aegis start
```

After the first start, manage it from the same checkout:

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
