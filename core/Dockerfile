FROM python:3.11-alpine AS base

# Security: Create non-root user
RUN adduser -D -H -s /bin/sh vivified

# Install runtime packages
RUN apk add --no-cache curl

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=vivified:vivified . .

# Security: Run as non-root
USER vivified

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; import sys; import os;\n+import urllib.request as u;\n+u.urlopen('http://localhost:8000/health'); sys.exit(0)" || exit 1

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
