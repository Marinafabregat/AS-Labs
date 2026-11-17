# AS Lab

## 1. Project Directory Structure


```text
AS/
├── main.py
├── models.py
├── db.py
├── auth.py
├── oauth.py
├── service.py
├── REQUIREMENTS.txt
├── .env
├── uploads/
│   └── images or other files (this we have to encrypt)
├── routes/
│   └── admin.py,items.py,mod.py,oauth_routes.py,users.py
├── static/
│   └── (css, js, images)
└── templates/
   └── *.html files

```
main.py: initial webapp logic, links the routes for the rest of the api
routes/file.py: this holds the actuapi API logic for the webapp, so homepage, users, items being added, etc,etc.
models.py: stores the models for the db tables
db.py: holds the functions to begin the db engince with which we can handle the database

(These two files might need to be adapted)
auth.py: handles password hashing, current-user dependencies and access control.
oauth.py: configures the Google OAuth client.
routes/oauth_routes.py: handles Google OAuth login, account linking and unlinking.
service.py: holds the oauth2 scheme
---

## 2. Virtual Environment Setup


1. **Create the virtual environment:**
   ```bash
   python -m venv venv
   ```

2. **Activate the virtual environment:**
   * **Windows (Command Prompt / PowerShell):**
     ```cmd
     venv\Scripts\activate
     ```
   * **macOS / Linux:**
     ```bash
     source venv/bin/activate
     ```

---

## 3. Install Dependencies
MORE THINGS WILL HAVE TO BE INSTALLED, PUT THEM IN REQUIREMENTS.txt AS THE NEED ARISES

Install the required packages using `pip`:

```bash
pip install fastapi uvicorn sqlalchemy pyjwt requests python-dotenv jinja2 ...
```
```bash
pip install -r REQUIREMENTS.txt
```
---


## 4. Running the Application

### Local Development

Start the server using **Uvicorn** with the reload flag enabled (so changes update automatically):

```bash
uvicorn main:app --reload
```

### With Docker

**Prerequisites:** Docker Desktop (Windows/Mac) or Docker Engine (Linux)

1. **Build and start the container:**
   ```bash
   docker compose up --build -d
   ```

2. **Access the app at:** https://localhost:8000

3. **View logs:**
   ```bash
   docker compose logs -f
   ```

4. **Stop the container:**
   ```bash
   docker compose down
   ```

**Persistence:** The following are persisted on the host via bind mounts:
- `database.db` - SQLite database
- `uploads/` - User uploaded files
- `.env` - Environment variables (mounted read-only)
- Source code - Live reload via bind mount

**Note:** For local development without Docker, comment line 6 and uncomment line 8 in `db.py` to use relative path `database.db`.

---

## 5. Dynamic Application Security Testing (DAST) with OWASP ZAP

The repository includes an [OWASP ZAP](https://www.zaproxy.org/) Automation Framework plan for authenticated dynamic scanning.

### Prerequisites

- Docker Engine or Docker Desktop.
- On WSL, enable **Docker Desktop > Settings > Resources > WSL Integration** for the distro, or install Docker Engine inside WSL.
- The scan stack creates a throwaway database (`/tmp/zap-scan.db`) and seeds the test accounts automatically, so it does not touch `database.db` on the host.

### Run the scan

```bash
./scripts/run-zap.sh
```

The script:

1. Builds and starts an isolated app container (`vinsec-app-scan`) with `SESSION_HTTPS_ONLY=false`, a throwaway SQLite database and an isolated `uploads` volume.
2. Runs ZAP against `http://app:8000` using the three seed roles.
3. Writes the reports to `zap/reports/zap-report.html` and `zap/reports/zap-report.json`.
4. Removes the scan containers, the throwaway database and the isolated uploads volume.

You can also run the steps manually:

```bash
docker compose -p vinsec-scan -f docker-compose.yml -f docker-compose.scan.yml up -d --build --wait app
docker compose -p vinsec-scan -f docker-compose.yml -f docker-compose.scan.yml --profile security run --rm --no-deps zap
docker compose -p vinsec-scan -f docker-compose.yml -f docker-compose.scan.yml down -v
```

### Scan configuration

- Plan: `zap/zap-plan.yaml`
- Context: `http://app:8000`
- Authentication: form-based login at `POST /users/login`
- Seed users:
  - `alice_seller` / `user123`
  - `moderator` / `mod123`
  - `admin` / `admin123`
- Jobs: insights (automatic plan abort disabled), spider, passive scan, active scan and HTML/JSON reports for each role.
- The OAuth flow, logout/delete endpoints, profile/account updates, registration, item creation/editing/liking/buying/reporting, moderator actions and destructive admin actions are excluded. In particular, `/users/update` must be excluded because the active scan would rewrite the seed users' passwords and invalidate their sessions mid-scan.

### Important caveats

- **Do not run the active scan against production or your development database.** Active scanning submits forms and can create, modify or delete data. The provided stack uses a disposable database for this reason.
- The scan targets plain HTTP inside the Docker network to avoid the self-signed nginx certificate. This is why the scan override disables the `Secure` session cookie flag. This plan tests the FastAPI application directly; to include nginx/TLS, change the context and login URLs in `zap/zap-plan.yaml` to `https://nginx:8000` and configure ZAP to trust the self-signed certificate.
- If the ZAP container cannot write to `zap/reports/`, check that the directory is writable by the container user (UID 1000 by default).
- Review and triage the findings; a successful scan does not by itself prove that the security controls work. Typical findings for this application are missing CSRF tokens, missing security headers, exposed `/docs` and `/openapi.json`, and the nginx server version banner.
