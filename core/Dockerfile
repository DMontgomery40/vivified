FROM python:3.11-alpine AS base

# Security: Create non-root user
RUN adduser -D -H -s /bin/sh vivified

# Install runtime packages
RUN apk add --no-cache curl openssl

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application under package path
COPY --chown=vivified:vivified . ./core
COPY --chown=vivified:vivified entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# Admin UI assets are optional; server serves a safe placeholder when dist is absent in DEV/CI

# Security: Run as non-root
USER vivified

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD sh -c 'curl -fsS http://localhost:8000/health >/dev/null 2>&1 || exit 1'

EXPOSE 8000 8443
ENTRYPOINT ["/entrypoint.sh"]
