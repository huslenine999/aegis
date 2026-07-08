# GitHub integration

Create a GitHub OAuth app with this callback URL:

```text
https://aegis.example.com/api/github/callback
```

Configure:

```bash
AEGIS_GITHUB_CLIENT_ID=...
AEGIS_GITHUB_CLIENT_SECRET=...
AEGIS_GITHUB_CALLBACK_URL=https://aegis.example.com/api/github/callback
AEGIS_ENCRYPTION_KEY=...
```

Generate an encryption key:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Restart dashboard and worker, open `/projects`, and select **Connect GitHub**.
Users can browse repositories available to their account and import public or
private repositories.

Tokens are encrypted in PostgreSQL. Repository clone credentials are supplied
through Git process environment configuration and are not included in command
arguments or logs.

## Main branch protection

Protect `main` with a GitHub branch rule or repository ruleset before enabling
auto-merge. Require pull requests, dismiss stale approvals, require branches to
be up to date, and block force pushes/deletions.

Mark these checks as required status checks:

- `Aegis Project Approval Gate`
- `Validate CLI and Policy`
- `Production Container Smoke`

The release workflow runs on tags and manual dispatches, so it should remain a
release gate rather than a required pull-request check.
