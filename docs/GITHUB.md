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
