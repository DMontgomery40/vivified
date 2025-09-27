# Vivified Platform — Phase 1 Scaffold

This repository contains the Phase 1 scaffold for the Vivified platform: a minimal core service, plugin interface contracts, an example plugin, and Docker Compose wiring.

Quick start

- Prereqs: Docker, Docker Compose
- Start stack: `make up`
- Stop stack: `make down`

Services

- Core: FastAPI app exposing `/health` and plugin registration endpoints
- Example Plugin: `user_management` service, registers itself with core on startup

Commands

- `make build` — Build Docker images
- `make up` — Bring up services
- `make down` — Tear down services
- `make test` — Run unit tests
- `make lint` — Run linters
- `make proto` — Compile protobufs

Notes

- Containers run as non-root users
- Registration endpoint is open for Phase 1 (no auth yet)
- JWT secret and DB password are provided via environment variables
