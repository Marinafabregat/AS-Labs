# Development Guide

## Running

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r REQUIREMENTS.txt

docker compose up -d authzforce   # required: the app denies everything without it
uvicorn main:app --reload
```

Dependencies are pinned nowhere yet; `REQUIREMENTS.txt` lists them without versions and keeps the historical uppercase filename used by the Dockerfile.

## Routes by role

All paths are relative to the host and port where the app listens.

### Public

| Method | Path | Notes |
|--------|------|-------|
| GET | `/` | Home page; items filtered through XACML `read` |
| GET/POST | `/users/register` | Account creation |
| GET/POST | `/users/login` | Session creation |
| GET | `/users/logout` | Clears the session |
| GET | `/auth/login` | Google-only login page |
| GET | `/auth/google` | Starts the Google OAuth redirect |
| GET | `/auth/callback` | OAuth callback; creates or links the account |
| GET | `/items/{item_id}` | Item detail; hidden items only for staff |
| GET | `/items/{item_id}/image` | Decrypts and returns the image after the XACML check |
| GET | `/users/{user_id}` | Public profile, subject to the privacy policy |

### Authenticated users

| Method | Path | Notes |
|--------|------|-------|
| GET | `/users/profile` | Own profile and PII |
| POST | `/users/update` | Updates own data; CSRF-protected |
| POST | `/users/delete` | Deletes own account; CSRF-protected |
| GET/POST | `/users/mod-petition` | Submit a moderator application |
| POST | `/users/mod-petition/cancel` | Withdraw the application |
| POST | `/users/{user_id}/report` | Report another account |
| GET/POST | `/items/create` | Create a listing |
| GET/POST | `/items/{item_id}/edit` | Edit an owned listing |
| POST | `/items/{item_id}/delete` | Delete an owned listing |
| POST | `/items/{item_id}/like` | Like/unlike |
| POST | `/items/{item_id}/buy` | Buy an item |
| POST | `/items/{item_id}/report` | Report an item |
| GET | `/items/liked` | Liked items |
| GET | `/items/purchased` | Purchases |
| GET | `/items/my-items` | Listings owned by the user |
| GET | `/auth/google/link` | Link Google from the profile |
| POST | `/auth/unlink` | Unlink Google; CSRF-protected |

### Moderator (`/mod`)

| Method | Path |
|--------|------|
| GET | `/mod/moderator-reports` |
| POST | `/mod/moderator-reports/users/{report_id}/accept` |
| POST | `/mod/moderator-reports/users/{report_id}/dismiss` |
| POST | `/mod/moderator-reports/items/{report_id}/accept` |
| POST | `/mod/moderator-reports/items/{report_id}/dismiss` |

### Admin (`/admin`)

| Method | Path |
|--------|------|
| GET | `/admin/admin-reports` |
| POST | `/admin/admin-reports/users/{report_id}/ban` |
| POST | `/admin/admin-reports/users/{report_id}/revert` |
| POST | `/admin/admin-reports/users/{user_id}/unban` |
| POST | `/admin/admin-reports/users/{user_id}/delete` |
| POST | `/admin/admin-reports/items/{report_id}/revert` |
| POST | `/admin/admin-reports/items/{item_id}/delete` |
| POST | `/admin/mod-petitions/{petition_id}/approve` |
| POST | `/admin/mod-petitions/{petition_id}/reject` |

## Database

`db.py` creates the engine from `DATABASE_URL`, falling back to SQLite in the project directory (or `/app/database.db` in Docker). `init_db()` creates missing tables and applies a small in-place migration for the `is_banned` column; there is no migration framework.

Reset locally:

```bash
rm database.db
rm -f uploads/*.enc        # optional: also drops encrypted images
```

The next start recreates the schema and seeds the four test accounts.

`seed_default_data()` runs only when the database file did not exist, so deleting individual rows does not bring them back.

## Tests and helper tools

`pytest`, `pytest-asyncio`, `pytest-cov` and `httpx` are installed, but no test suite is committed. The `tools/` directory contains static checks used while developing. 

Run the security scan with `./scripts/run-zap.sh` (see
[security-testing.md](security-testing.md)).

## Conventions

- Authorization decisions belong in `authz.py` / the XACML policy, not in templates or route bodies. `tools/check_access_bypass.py` and `tools/check_templates.py` enforce this.
- New protected resource types need: a policy in `_build_policy_set()`, an attribute helper, and `can()`/`enforce()` calls in the handler.
