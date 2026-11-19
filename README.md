# VINSEC Marketplace

Online marketplace built for the Application Security course. The FastAPI app delegates every access decision to an external XACML Policy Decision Point (AuthzForce), so authentication, roles and ownership rules live in a policy
rather than in the route handlers.

## Features

- Three roles (`user`, `moderator`, `admin`) enforced by XACML 3.0`deny-overrides` policies
- Session authentication with Argon2 password hashes and CSRF-protected forms
- Optional Google OAuth login, with account linking/unlinking from the profile
- Uploaded images encrypted at rest with AES-256-GCM; PII and OAuth tokens withFernet
- Nginx TLS reverse proxy and hardened security headers
- Authenticated OWASP ZAP scan setup

## Stack

Python 3.11 · FastAPI · SQLModel/SQLite · AuthzForce CE · Nginx · Docker

## Quick start (Docker)

Requires Docker Engine or Docker Desktop.

```bash
# 1. Create a .env file (required keys: docs/configuration.md)
# 2. Build and start the stack
docker compose up --build -d
```

Open <https://localhost:8000> (or <https://localhost>) and accept the self-signed certificate. Stop the stack with `docker compose down`.

The database is seeded on first start with these development accounts:

| Role      | Username      | Password   |
|-----------|---------------|------------|
| Admin     | `admin`       | `admin123` |
| Moderator | `moderator`   | `mod123`   |
| User      | `alice_seller`| `user123`  |
| User      | `bob_buyer`   | `user123`  |

Change or remove these accounts before exposing the application to anyone.

## Local development

AuthzForce is still required; the app denies every request without it.

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r REQUIREMENTS.txt

docker compose up -d authzforce   # PDP on http://localhost:8080
uvicorn main:app --reload         # app on http://localhost:8000
```

The SQLite file and seed data are created automatically on first start. Use `DATABASE_URL` to point at a different database.

## Configuration

Settings are read from `.env`. Docker deployments refuse to start without `SESSION_SECRET_KEY`, `PII_ENCRYPTION_KEY` and `IMAGE_ENCRYPTION_KEY`.
All variables, defaults and key-generation commands are documented in [docs/configuration.md](docs/configuration.md).

## Project layout

```text
main.py                  FastAPI app, middleware, startup and seed data
routes/                  users, items, moderation, admin and OAuth endpoints
models.py / db.py        SQLModel tables and database engine
auth.py                  sessions, password hashing, CSRF tokens
authz.py                 XACML PEP/PAP: policy set, attributes, can()/enforce()
marketplace_policy.xml   Policy reference copy (generated in authz.py at runtime)
security_encryption.py   Fernet (PII) and AES-256-GCM (images)
image_storage.py         Encrypted upload storage and legacy migration
nginx/                   TLS reverse proxy configuration
zap/, scripts/           Authenticated OWASP ZAP scan
```

The FastAPI docs endpoints (`/docs`, `/redoc`, `/openapi.json`) are disabled.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/architecture.md](docs/architecture.md) | Components, request flow, XACML model, data model |
| [docs/configuration.md](docs/configuration.md) | Environment variables and key generation |
| [docs/security-testing.md](docs/security-testing.md) | OWASP ZAP scan: how to run and configure |
| [docs/development.md](docs/development.md) | Routes by role, database, tests and helper tools |

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
