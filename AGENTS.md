# SentinelSpawn / Monster Spawned Studios — Agent Notes

## Cursor Cloud specific instructions

### What this repo is
- A Docker Compose network-security monitoring stack: **Suricata** (NIDS), **EveBox**
  (alert dashboard), **Prometheus + Grafana** (metrics), **Cloudflare Tunnel**, and Python
  helper services in `notifier/` (notifier, suricata metrics exporter, banIP updater,
  C2 blocker). See `README.md` and `docker-compose.yml`.
- The actively-developed, source-controlled application is the **`dashboard/` FastAPI app**
  ("SentinelSpawn Command Center") — `dashboard/main.py` + `dashboard/auth.py` with Jinja2
  templates in `dashboard/templates/`. This is the piece you can run and test in the cloud VM.

### Scope in the cloud VM
- The full `docker compose` stack is **not runnable here**: Docker is not installed, and
  Suricata requires host packet capture (`network_mode: host`, `NET_RAW`/`NET_ADMIN`) on a
  real monitoring interface. Treat the compose stack as production/integration deployment
  (run via `docker compose up -d` or `deploy.sh` on a Linux host; edit the `-i eth0`
  interface in `docker-compose.yml` and provide a `.env`). Dev work targets the dashboard app.

### Python environment
- Dependencies live in `/workspace/.venv` (refreshed by the update script). Deps mirror
  `dashboard/Dockerfile` plus `python-multipart` (FastAPI needs it for form posts).
- **FastAPI is pinned to `0.111.1`** (→ Starlette 0.37.2). The dashboard code uses the legacy
  `templates.TemplateResponse("name.html", {"request": request})` signature, which breaks on
  modern Starlette (>= ~1.x) with `TypeError: unhashable type: 'dict'`. Do not bump
  FastAPI/Starlette without first migrating the template calls to the `request`-first signature.

### Running the dashboard
- `SECRET_KEY` env var is **required** (the app raises on startup without it). It must be a
  valid Fernet key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
- `dashboard/auth.py` hardcodes the SQLite DB at `/app/data/users.db`. That directory must
  exist and be writable: `sudo mkdir -p /app/data && sudo chown -R "$USER" /app`.
- Run from the `dashboard/` directory (templates/static paths are relative). Port 8080:
  ```bash
  cd dashboard
  SECRET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
    /workspace/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080
  ```
  Note: changing `SECRET_KEY` invalidates the stored TOTP secret of existing users — keep it
  stable across restarts (export once), or delete `/app/data/users.db` to re-run first-time setup.

### Auth flow gotchas (important for testing)
- Flow: `/setup` (create first admin) → `/login` (username+password) → `/login/mfa` (TOTP)
  → first login forces `/change-password` → `/dashboard`.
- The MFA `challenge_id` from `/login` **expires after 5 minutes**, and TOTP codes rotate
  every **30 seconds**. Both must be fresh at submit time — a stale challenge makes every code
  fail with "Invalid credentials or TOTP code" regardless of correctness.
- To script the flow, decrypt the user's TOTP secret from the DB with the same `SECRET_KEY`
  (`cryptography.fernet.Fernet`) and generate codes with `pyotp`.

### Lint / tests
- No automated test suite and no linter config are committed. `python -m py_compile` on the
  Python sources is a reasonable smoke check.
