#!/bin/sh
# Entrypoint for the ADMIN service (admin.huntr.run) — NOT the public API.
#
# Why a script: gunicorn does not expand environment variables inside -b, and Railway exec's a
# service's Custom Start Command as raw argv (no shell), so `-b 0.0.0.0:$PORT` passed directly reaches
# gunicorn as the literal string "$PORT" → "'$PORT' is not a valid port number". This script runs in
# its own /bin/sh, so ${PORT} expands here before gunicorn ever sees it.
#
# Railway Custom Start Command for the admin service:  sh start-admin.sh
exec gunicorn app.admin_app:app \
  -k uvicorn.workers.UvicornWorker \
  -w 2 \
  -b "0.0.0.0:${PORT:-8080}" \
  --access-logfile - \
  --error-logfile - \
  --timeout 30
