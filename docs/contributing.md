# Contributing

Development workflow

- Create a feature branch off `development`
- Follow conventional commits (e.g., `feat(core): add X`)
- Add/Update tests and docs with any code changes
- Open a PR and ensure CI passes

Documentation

- Docs live under `docs/` and are built with MkDocs
- Versioning is managed with `mike` (alias `latest` tracks the dev docs)
- CI validates docs with `mkdocs build --strict`

Make targets

- `make docs` — Build docs site locally
- `make docs-serve` — Serve docs locally at http://127.0.0.1:8000
