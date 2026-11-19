# Configuration

Settings are loaded from `.env` (via `python-dotenv`) and from the process
environment. `docker-compose.yml` also injects `AUTHZFORCE_BASE_URL`, so the
app reaches the PDP by service name inside the Docker network.

## Environment variables

| Variable | Required in Docker | Default | Purpose |
|----------|--------------------|---------|---------|
| `SESSION_SECRET_KEY` | Yes | Random value per process (local only) | Signs the session cookie. Rotating it logs everyone out. |
| `PII_ENCRYPTION_KEY` | Yes | Insecure development key | Fernet key for delivery PII and OAuth tokens. |
| `IMAGE_ENCRYPTION_KEY` | Yes | Insecure development key | Base64-encoded 32-byte key for AES-256-GCM image encryption. |
| `DATABASE_URL` | No | `sqlite:////app/database.db` in Docker, `sqlite:///<repo>/database.db` locally | SQLAlchemy URL. `sqlite:////app/...` paths are ignored outside Docker. |
| `AUTHZFORCE_BASE_URL` | No | `http://localhost:8080/authzforce-ce` | AuthzForce REST base URL. Compose sets `http://authzforce:8080/authzforce-ce`. |
| `SESSION_HTTPS_ONLY` | No | `true` in Docker, `false` elsewhere | Marks the session cookie `Secure`. Set to `false` only for plain-HTTP scanning or local HTTP. |
| `GOOGLE_CLIENT_ID` | No | – | Google OAuth client ID. |
| `GOOGLE_CLIENT_SECRET` | No | – | Google OAuth client secret. |
| `GOOGLE_REDIRECT_URI` | No | Generated callback URL | Must match the URI registered in Google Cloud. |

In Docker the app raises `RuntimeError` at startup if `SESSION_SECRET_KEY`,
`PII_ENCRYPTION_KEY` or `IMAGE_ENCRYPTION_KEY` are missing. Outside Docker it
logs a warning and falls back to insecure development keys.

Docker detection is `os.path.exists("/app")`; keep that in mind if you deploy
outside the provided image.

## Generating keys

```bash
# Session secret
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Fernet key (PII / OAuth tokens)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# AES-256 key, Base64 (images)
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

Minimum `.env` for Docker:

```dotenv
SESSION_SECRET_KEY=<generated value>
PII_ENCRYPTION_KEY=<generated Fernet key>
IMAGE_ENCRYPTION_KEY=<generated Base64 key>
```

## Google OAuth (optional)

1. Create a Web application credential in Google Cloud Console.
2. Add the callback as an authorised redirect URI, for example
   `https://localhost:8000/auth/callback` (or `https://localhost/auth/callback`).
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `GOOGLE_REDIRECT_URI`.

Without these values the username/password login still works; only the Google
button fails.

## Database

- SQLite is the default. The file is created on first start and then seeded.
- To reset the application, stop the stack and delete `database.db` (plus
  `uploads/*.enc` if you also want to drop images). The next start recreates and
  seeds everything.
- `docker-compose.scan.yml` points `DATABASE_URL` at `/tmp/zap-scan.db` so the
  active scan never touches development data.

## Security note about `.env`

`.env` is currently tracked by git. Before publishing the repository:

```bash
git rm --cached .env
printf '\n.env\n' >> .gitignore
```

Then rotate every key that was committed. Do not rely on the development
fallback keys outside a local machine.
