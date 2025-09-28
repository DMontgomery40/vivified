# Getting Started

This guide helps you run the Phase 1 scaffold locally.

Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local testing)

Quick start

1. Build and start: `make up`
2. Check core health: `curl http://localhost:8000/health`
3. Verify plugin registration: `curl http://localhost:8000/plugins`

Development commands

- `make test` — Runs unit tests
- `make lint` — Runs linters
- `make proto` — Compiles protobufs
- `make down` — Stops services

Next steps

- Read Core Overview to see how plugin registration works in Phase 1.
