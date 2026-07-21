# GitHub integration

Aegis uses two separate GitHub integrations:

- A GitHub OAuth app lets dashboard users browse and import repositories.
- A GitHub App receives pull-request events, checks out the exact head commit,
  runs the security gate, and publishes a check run with inline findings.

## OAuth app

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

Generate the database credential-encryption key:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Restart dashboard and worker, open `/projects`, and select **Connect GitHub**.
OAuth tokens are encrypted in PostgreSQL. Clone credentials are supplied through
the Git process environment and are never included in command arguments or logs.

## GitHub App pull-request gate

Create a GitHub App owned by the organization that will install Aegis. Configure:

- Webhook URL: `https://aegis.example.com/api/github/webhook`
- Webhook secret: a randomly generated value of at least 32 characters
- Repository permissions: **Checks: read and write**, **Contents: read**, and
  **Metadata: read**
- Subscribe to the **Pull request** event
- Install the App only on repositories that Aegis is authorized to scan

Export the App private key as base64 so the multiline PEM survives container
environment handling:

```bash
base64 < aegis-app.private-key.pem | tr -d '\n'
```

Configure both dashboard and worker:

```bash
AEGIS_PUBLIC_URL=https://aegis.example.com
AEGIS_GITHUB_APP_ID=123456
AEGIS_GITHUB_APP_PRIVATE_KEY_B64=...
AEGIS_GITHUB_WEBHOOK_SECRET=...
```

The dashboard verifies the webhook HMAC and replay identifier, creates an
in-progress check on the pull request head SHA, and queues that immutable
revision. The worker obtains a short-lived installation token, fetches only the
requested revision, and completes the check. Ruff, Semgrep, and secret findings
with repository locations are emitted as inline annotations; the Aegis policy
verdict controls the check conclusion.

Validate with a non-production repository before enabling the required check:

1. Open a pull request containing one known benchmark vulnerability.
2. Confirm one webhook delivery creates one Aegis scan and an in-progress check.
3. Confirm the scan manifest revision equals the pull request head SHA.
4. Confirm the finding appears inline and the check blocks.
5. Push a remediation commit and confirm a new check passes on the new SHA.
6. Redeliver a failed webhook and confirm a successful delivery cannot be replayed.

Fork pull requests and organization SSO policies vary, so include both in pilot
acceptance testing. Installation tokens are short-lived; the long-lived App key
must remain in the deployment secret manager and should be rotated periodically.

## Main branch and release protection

Protect `main` with a GitHub ruleset. Require pull requests, dismiss stale
approvals, require branches to be up to date, block force pushes/deletions, and
require these checks:

- `Aegis security gate`
- `Aegis Project Approval Gate`
- `Validate CLI and Policy`
- `Production Container Smoke`

Create the `production-release` environment with an independent required
reviewer. The release workflow runs on tags and manual dispatches; environment
approval is the human promotion gate for publishing the container.
