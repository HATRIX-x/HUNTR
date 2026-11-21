# HUNTR Admin dashboard — deploy

A **standalone, read-only** metrics dashboard (signups, activation funnel, usage, revenue). It runs
as its **own Railway service on its own subdomain** — it is NOT part of the public API (`api.huntr.run`),
so no bug in the public API can reach it. Code: `cloud/app/admin_app.py`.

## Why separate

- **Process isolation** — the admin endpoints never exist in the public API process.
- **Own login** — `localStorage` is per-origin, so the admin subdomain can't reuse the main site's
  session. The app authenticates you directly against the shared `users` table using your existing
  password + TOTP (+ single-use backup codes) and the same DB-backed lockout.
- **Fail-closed** — access is gated by `ADMIN_EMAILS`. Unset ⇒ nobody is an admin.

## One-time setup (Railway dashboard)

1. **New service** in the same Railway project, from the same GitHub repo.
2. **Root Directory** = `cloud`.
3. **Config-as-code path** = `cloud/railway.admin.toml` (sets the start command + `/health` check).
   - Or skip the file and set a Custom Start Command:
     `gunicorn app.admin_app:app -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:$PORT`
4. **Variables** (Service → Variables):
   - `DATABASE_URL` → reference the **same Postgres** as the API (`${{Postgres.DATABASE_URL}}`).
   - `ADMIN_EMAILS` → your email(s), comma-separated (e.g. `moustafa.rashid1001@gmail.com`).
   - `SECRET_KEY` → a **new, distinct** random value (NOT the API's). Distinct = admin tokens and API
     tokens can't be used against each other. Generate: `python3 -c "import secrets;print(secrets.token_urlsafe(48))"`.
   - (optional) `AUTH_MAX_FAILURES`, `AUTH_LOCK_MINUTES` — lockout tuning (defaults 5 / 15).
5. **Custom domain** → add `admin.huntr.run` (or an unguessable subdomain) and point the DNS CNAME at
   the Railway target it shows.

## Verify

- `https://admin.huntr.run/health` → `{"ok":true}`
- Open `https://admin.huntr.run/`, sign in with your account + 2FA → dashboard loads.
- A non-admin account (or no login) can't read `/metrics.json` (401/opaque 404).

## Hardening options (later, if wanted)

- Put the service behind Railway **private networking** / an IP allowlist and reach it via a tunnel
  (removes it from the public internet entirely).
- Add Cloudflare Access in front of `admin.huntr.run` for a second, independent auth layer.
