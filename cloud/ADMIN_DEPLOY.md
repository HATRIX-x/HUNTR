# HUNTR Admin dashboard — deploy

A **standalone, read-only** metrics dashboard (signups, activation funnel, usage, revenue). It runs
as its **own Railway service on its own subdomain** — it is NOT part of the public API (`api.huntr.run`),
so no bug in the public API can reach it. Code: `cloud/app/admin_app.py`.

## Why separate

- **Process isolation** — the admin endpoints never exist in the public API process.
- **Own login** — `localStorage` is per-origin, so the admin subdomain can't reuse the main site's
  session. The app authenticates you directly against the shared `users` table using your existing
  password + TOTP (+ single-use backup codes) and the same DB-backed lockout (reused from app.auth).
- **Fail-closed** — access is gated by `ADMIN_EMAILS`. Unset ⇒ nobody is an admin.

## Railway service setup

Create a second service in the same project, from the same GitHub repo.

1. **Settings → Source**
   - **Source Repo**: `HATRIX-x/HUNTR`
   - **Root Directory**: `cloud`
   - **Branch connected to production**: **`integrate`** — this is the branch that contains
     `admin_app.py` AND the auth functions it imports (verify_totp / is_locked / lockout / backup
     codes). `main` is currently ~184 commits behind and is MISSING those functions, so a build from
     `main` would crash on import. (Promote integrate→main first if you want to deploy from `main`.)
2. **Settings → Deploy → Custom Start Command** (required):
   ```
   sh start-admin.sh
   ```
   The repo's `cloud/Dockerfile` is the API's — its `CMD` runs `app.main:app` on a hardcoded port.
   This start command overrides it so the service runs the ADMIN app instead. It calls
   `cloud/start-admin.sh`, which execs gunicorn and binds `$PORT` from inside a real shell — passing
   `-b 0.0.0.0:$PORT` directly fails ("'$PORT' is not a valid port number") because Railway exec's the
   start command as raw argv, so `$PORT` never expands. (Config-as-code / `railway.*.toml` is
   deprecated on Railway — use this field, not a toml.)
3. **Variables**:
   - `DATABASE_URL` → the **same Postgres** as the API (`${{Postgres.DATABASE_URL}}`).
   - `ADMIN_EMAILS` → your email(s), comma-separated.
   - `SECRET_KEY` → a **new, distinct** random value (NOT the API's), so admin and API tokens can't be
     used against each other. Generate: `python3 -c "import secrets;print(secrets.token_urlsafe(48))"`.
   - (optional) `AUTH_MAX_FAILURES`, `AUTH_LOCK_MINUTES` — lockout tuning (defaults 5 / 15).
4. **Custom domain** → add `admin.huntr.run` (or an unguessable subdomain) and set the CNAME +
   `_railway-verify` TXT records Railway shows, at your DNS provider.

## Verify

- `https://admin.huntr.run/health` → `{"ok":true}`
- Open `https://admin.huntr.run/`, sign in with your account + 2FA → dashboard loads.
- A non-admin account (or no login) can't read `/metrics.json` (401 / opaque 404).

## Hardening options (later, if wanted)

- Put the service behind Railway **private networking** / an IP allowlist and reach it via a tunnel
  (removes it from the public internet entirely).
- Add Cloudflare Access in front of `admin.huntr.run` for a second, independent auth layer.
