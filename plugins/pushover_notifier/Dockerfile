FROM python:3.11-alpine AS base

# Security: non-root user
RUN adduser -D -H -s /bin/sh plugin

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=plugin:plugin . .
USER plugin

EXPOSE 8012
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8012"]

