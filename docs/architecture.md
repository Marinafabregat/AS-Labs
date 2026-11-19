# Architecture

## Components

```text
Browser
  │  HTTPS
  ▼
Nginx (TLS termination, HTTP → HTTPS redirect)
  │  HTTP (Docker network)
  ▼
FastAPI app (uvicorn)
  ├─ SessionMiddleware + security headers
  ├─ routes/*.py ──► PEP: can() / enforce()
  │                        │  XACML request (XML over HTTP)
  │                        ▼
  │                  AuthzForce CE (PDP)
  ├─ SQLModel ──► SQLite (`database.db`)
  └─ uploads/ ──► AES-256-GCM encrypted files
```

| Component | Role |
|-----------|------|
| `nginx/nginx.conf` | TLS 1.2/1.3 termination on ports 443 and 8000, redirects port 80 to HTTPS, proxies to `app:8000` |
| `main.py` | App factory, lifespan startup, middleware, exception handlers, home page |
| `routes/` | HTTP endpoints; every sensitive handler asks the PDP before acting |
| `authz.py` | Policy Administration Point (builds/publishes the policy set) and Policy Enforcement Point (`can`, `enforce`) |
| `authzforce` service | External XACML 3.0 PDP (`fiware/authzforce-ce-server`) |
| `models.py`, `db.py` | SQLModel tables, engine, lightweight migrations, seed data |
| `security_encryption.py` | Fernet for PII/OAuth tokens, AES-256-GCM for images |
| `image_storage.py` | Encrypted upload writes, reads and legacy plaintext migration |

## Startup sequence

`main.py` runs these steps in the lifespan hook:

1. `init_authzforce()` waits up to 30 × 2 s for AuthzForce, finds or creates the
   `Marketplace` domain, publishes a new PolicySet version (`2.1.<epoch>`),
   binds it as the PDP root policy and runs an in-process self-test.
2. `migrate_plaintext_uploads()` encrypts any legacy plaintext images.
3. `init_db()` creates missing tables, adds the `is_banned` column to old
   databases and clears stale blacklist flags with no active escalation.
4. If the database did not exist, `seed_default_data()` creates categories,
   items, test interactions and the four development accounts.

Publishing a new policy version on every start avoids deleting the version the
PDP may currently be using, which AuthzForce rejects.

## Request lifecycle

1. Starlette `SessionMiddleware` loads the signed session cookie into
   `request.session` (HTTP-only, `SameSite=Lax`, 8 h lifetime).
2. A dependency resolves the caller: `get_current_user_optional` (anonymous
   allowed) or `get_current_active_user` (401 if missing or disallowed).
3. The handler calls `can(user, action, resource_type, attrs)` to filter lists,
   or `enforce(...)` to abort with 401/403.
4. The PEP builds an XACML request (subject, action, resource type and
   resource attributes) and POSTs it to the PDP.
5. Only a `Permit` decision allows the action. `Deny`, `NotApplicable`,
   `Indeterminate`, timeouts and transport errors all deny (**fail closed**).
6. The security-headers middleware adds `X-Frame-Options`, `nosniff`, CSP,
   HSTS and `X-Application` to the response.

Exceptions are rendered as HTML through `templates/error.html`; FastAPI's
`/docs`, `/redoc` and `/openapi.json` endpoints are disabled.

## XACML model

- PolicySet: `marketplace-policyset`, combining algorithm **deny-overrides**
  (a single matching `Deny` wins over any `Permit`).
- Policies and main actions:

| Policy | Resource type | Actions |
|--------|---------------|---------|
| `account-status-policy` | any | Blocks everything except `read` for banned/blacklisted users |
| `account-session-policy` | `account` | `session` |
| `items-policy` | `item` | `read`, `create`, `update`, `delete`, `like`, `buy`, `report_remove` |
| `report-policy` | `report` | `create`, `read`, `decide`, `escalated_decide`, `create_escalated` |
| `admin-action-policy` | `admin_action` | `view`, `ban`, `unban`, `revert`, `delete_user` |
| `mod-petition-policy` | `mod_petition` | `create`, `read`, `delete`, `review` |
| `user-profile-policy` | `user_profile` | `read` |
| `user-pii-policy` | `user_pii` | `read`, `update`, `delete` |
| `user-policy` | `user` | `create` (registration), `login` |

- Subject attributes: `subject-id`, `role` (`user`, `moderator`, `admin` or
  `anonymous`), `authenticated`, `is_banned`, `is_blacklisted`.
- Resource attributes include `owner_id`, `reporter_id`, `status`,
  `target_role`, `applicant_role`, `is_blacklisted`, `is_banned`.
- Representative rules:
  - Hidden items are readable/likeable/buyable only by staff.
  - Users cannot buy their own items and cannot report themselves.
  - Moderators cannot decide reports that are not `pending`, and cannot act on
    reports whose target is an administrator.
  - Administrators cannot apply `ban`, `unban`, `delete_user` or `revert` to
    their own account.
  - Suspended profiles are visible only to their owner and moderators.
  - Banned or blacklisted accounts cannot start a session.

Attribute helpers (`item_attrs`, `user_profile_attrs`, `user_pii_attrs`,
`report_create_attrs`, `item_report_attrs`, `petition_review_attrs`, ...) keep
the attribute names used by the policy in one place.

`marketplace_policy.xml` is a reference copy of the policy. The source of
truth is `_build_policy_set()` in `authz.py`; the XML file is not read at
runtime. `casbin_enforcer.py`, `model.conf` and `policy.csv` are an unused
earlier prototype.

## Data model

| Table | Purpose |
|-------|---------|
| `User` | Account, role, ban state, encrypted delivery PII, OAuth link and tokens |
| `Category` | Item category |
| `Item` | Listing owned by a seller; `is_blacklisted` hides it from non-staff |
| `Purchase` | One purchase per item (unique `item_id`), stores the historical price |
| `Like` | Saved item per user |
| `ItemReport` | User report against an item; status `pending`, `for_admin`, `resolved`, `dismissed` |
| `UserReport` | Report against an account, same status flow |
| `ModPetition` | Application to become moderator, reviewed by an admin |

## Authentication and OAuth

- Passwords are hashed with Argon2 via `passlib`; verification is constant-time
  inside the library. Passwords are truncated to 72 bytes for compatibility
  with legacy hashes.
- Registration enforces at least 8 characters, one uppercase letter, one digit
  and one special character.
- Login checks credentials first, then asks XACML (`login` on `user`) whether
  the account may start a session; the session is cleared and only `user_id`
  is stored.
- Google OAuth (`/auth/google` → Google → `/auth/callback`) is optional.
  Linking and unlinking happen from the profile page, and OAuth tokens are
  stored encrypted.
- State-changing handlers verify a per-session CSRF token against the session
  value. The login and registration POSTs are the exceptions (see
  [security.md](security.md)).

## Files and encryption

- Uploads are validated against a strict filename allowlist, encrypted with
  AES-256-GCM (12-byte random nonce + ciphertext + 16-byte tag) using the
  filename as associated data, and written atomically.
- Images are served only through `GET /items/{item_id}/image`, which checks
  authorization and decrypts in memory. `uploads/` is never mounted as static
  content.
- PII fields and OAuth tokens use Fernet (AES-128-CBC + HMAC).
