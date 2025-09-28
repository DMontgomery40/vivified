#!/bin/sh
set -e

PORT="${PORT:-8000}"

if [ "${USE_TLS:-false}" = "true" ]; then
  PORT=8443
  exec uvicorn core.main:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --ssl-keyfile "/certs/core.key" \
    --ssl-certfile "/certs/core.crt"
else
  exec uvicorn core.main:app --host 0.0.0.0 --port "${PORT}"
fi


