# Security Testing with OWASP ZAP

The repository includes an [OWASP ZAP](https://www.zaproxy.org/) Automation Framework plan that scans the application as three authenticated roles.

## What the scan does

1. Builds an isolated `app` container with a disposable SQLite database (`/tmp/zap-scan.db`), a separate `uploads` volume and `SESSION_HTTPS_ONLY=false`.
2. Runs ZAP against `http://app:8000` inside the Docker network.
3. For each role (`alice`, `moderator`, `admin`): spider, wait for passive scan, then active scan.
4. Writes an HTML and a JSON report to `zap/reports/`.
5. Removes the scan containers, database and uploads volume.

## Prerequisites

- Docker Engine or Docker Desktop.
- On WSL, enable **Docker Desktop → Settings → Resources → WSL Integration** for the distro, or install Docker Engine inside WSL.
- The stack never touches the development `database.db` or `uploads/`.

## Run the scan

```bash
./scripts/run-zap.sh
```

Reports:

- `zap/reports/zap-report.html`
- `zap/reports/zap-report.json`

The script starts from a clean stack every time and cleans up on exit, even if the scan fails.

## Manual run

```bash
docker compose -p vinsec-scan -f docker-compose.yml -f docker-compose.scan.yml up -d --build --wait app
docker compose -p vinsec-scan -f docker-compose.yml -f docker-compose.scan.yml --profile security run --rm --no-deps zap
docker compose -p vinsec-scan -f docker-compose.yml -f docker-compose.scan.yml down -v
```

## Scan configuration

Plan: `zap/zap-plan.yaml`

- Context: `http://app:8000` (plain HTTP inside the Docker network).
- Authentication: form login at `POST /users/login`, verified by polling `/users/profile` for the `Logout` link.
- Seed users:
  - `alice_seller` / `user123`
  - `moderator` / `mod123`
  - `admin` / `admin123`
- Jobs: insights (automatic abort disabled), spider, passive wait, active scan and reports, repeated for each user. Plan timeout is 30 minutes, with a 1-minute limit per rule and 5 minutes per active scan.
- `continueOnFailure: true`, so the remaining roles and the reports still run if one phase fails.

### Excluded paths

Excluded because ZAP cannot complete them or because they would break the session/data used by the next phase:

- OAuth: `/auth/google`, `/auth/callback`, `/auth/unlink`
- Logout and destructive deletes: `/users/logout`, `/auth/logout`, `/users/delete`, `/items/*/delete`
- State-changing forms that can rewrite seed data:
  `/users/update`, `/users/register`, `/users/mod-petition`, `/items/create`, `/items/*/edit`, `/items/*/like`, `/items/*/buy`, `/users/*/report`, `/items/*/report`
- Moderator decisions: `/mod/moderator-reports/...`
- Admin decisions: `/admin/admin-reports/...`, `/admin/mod-petitions/...`

The pages themselves are still crawled and scanned; only the state-changing POSTs are excluded. `/users/update` in particular must stay excluded because an active scan would rewrite the seed passwords and invalidate the sessions.

## Caveats

- **Never run the active scan against production or the development database.** It submits forms and can create, modify or delete data. The provided stack exists to contain that damage.
- The scan targets plain HTTP inside the Docker network to avoid the self-signed nginx certificate; that is why the scan override disables the `Secure` cookie flag. To include nginx/TLS, point the context and login URLs at `https://nginx:8000` and make ZAP trust the self-signed certificate.
- If the ZAP container cannot write to `zap/reports/`, check ownership (the container runs as UID 1000 by default).
- OAuth, CSRF token rotation and password changes are not covered; absence of findings does not prove those controls work.
- Triage the report. Typical findings for this application are missing CSRF tokens on some forms, CSP weaknesses, the self-signed certificate, nginx banner details and verbose error/log behaviour.
