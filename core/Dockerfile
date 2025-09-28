FROM node:20.19.5-alpine AS ui-build

WORKDIR /ui
# Only copy manifests first for better layer caching
COPY admin_ui/package*.json ./admin_ui/
RUN cd admin_ui && npm ci --no-audit --progress=false
# Copy UI source and build
COPY admin_ui ./admin_ui
RUN cd admin_ui && npm run build:dist

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
# Copy built Admin UI assets from the UI build stage into package
COPY --from=ui-build --chown=vivified:vivified /ui/admin_ui/dist ./core/admin_ui/dist

# Security: Run as non-root
USER vivified

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; import sys; import os;\n+import urllib.request as u;\n+u.urlopen('http://localhost:8000/health'); sys.exit(0)" || exit 1

EXPOSE 8000 8443
ENTRYPOINT ["/entrypoint.sh"]
