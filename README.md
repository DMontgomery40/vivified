# Vivi (kernel + polyglot plugins)

Packages:
- `vivified_core`: kernel + plugin API (traits + config-ready)
- `vivified_cli`: `vivi` CLI
- `vivified_api`: FastAPI server
- `plugins/hello_py`: native Python plugin
- `plugins/hello_js`: external Node plugin via JSON-RPC over stdio
- `plugins.d/*.json`: list external executables to auto-register
- `admin`: React + Vite admin console

## Quick start
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -U pip
pip install -e vivified_core -e vivified_cli -e vivified_api -e plugins/hello_py
vivi plugins
vivi run hello Vivi
vivi-api
# test:
# curl -s -X POST http://localhost:8787/run -H 'content-type: application/json' -d '{"plugin":"hello","args":["David"]}'
```

## Admin dev server
```bash
# API (with demo trait so you can run example plugins)
python3 -m venv .venv && . .venv/bin/activate && \
pip install -e vivified_core -e vivified_api -e plugins/hello_py && \
VIVI_TRAITS=demo vivi-api &

# Frontend
cd admin && \
echo 'VITE_API_BASE=http://localhost:8787' > .env.local && \
corepack pnpm i && corepack pnpm run dev
```

## Docker Compose
```bash
docker compose build && docker compose up -d
# UI: http://localhost:5173 (served by nginx)
# API: http://localhost:8787
```
