.PHONY: help build up down test lint proto clean

help:
	@echo "Available commands:"
	@echo "  make build   - Build all Docker images"
	@echo "  make up      - Start all services"
	@echo "  make down    - Stop all services"
	@echo "  make test    - Run tests"
	@echo "  make lint    - Run linters"
	@echo "  make proto   - Compile protobuf files"
	@echo "  make docs    - Build MkDocs site"
	@echo "  make docs-serve - Serve MkDocs locally"
	@echo "  make api-docs - Build static API docs (Swagger + Redoc) to site/api"
	@echo "  make ui-ci-local - Build React UIs (admin/ui) like CI"
	@echo "  make smoke-ai - Run local AI/RAG smoke test"
	@echo "  make clean   - Clean build artifacts"

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

test:
	pytest tests/ --cov=core --cov-report=html

	lint:
		black core/ plugins/
		flake8 core/ plugins/
		mypy core/

# Bootstrap local CI toolchain to match GitHub Actions
.PHONY: ci-bootstrap ci-local
ci-bootstrap:
	python3 -m pip install -q -r core/requirements.txt -c constraints.txt \
	  black flake8 mypy sqlalchemy pytest pytest-cov pytest-asyncio build

# Run the same checks as CI locally (fails on errors)
ci-local:
	python3 -m black --check core/
	python3 -m flake8 core/
	python3 -m mypy --config-file mypy.ini core/
	PYTHONPATH=$$(pwd):$$(pwd)/sdk/python/src python3 -m pytest -q
	$(MAKE) sdk-ci-local

# Build Admin Console and UI locally similar to CI
.PHONY: ui-ci-local
ui-ci-local:
	bash tools/scripts/ui_build.sh

.PHONY: smoke-ai
smoke-ai:
	@echo "[smoke-ai] Running RAG smoke test (requires core running)"
	@PY=$$(command -v python3.11 || echo python3); $$PY tools/scripts/rag_smoke.py --train --query "Vivified"

.PHONY: sdk-ci-local
sdk-ci-local:
	@echo "[sdk-ci] building python SDK package and running tests"
	python3 -m build sdk/python
	PYTHONPATH=$$(pwd)/sdk/python/src pytest -q sdk/python/tests

proto:
	protoc -I=core/proto --python_out=core/proto core/proto/*.proto

docs:
	python -m pip install -q mkdocs mkdocs-material mike
	mkdocs build --strict

docs-serve:
	python -m pip install -q mkdocs mkdocs-material mike
	mkdocs serve --dev-addr=127.0.0.1:8000

# Build static API docs (Swagger UI + Redoc) using app.openapi()
.PHONY: api-docs
api-docs:
	@PY=$$(command -v python3.11 || echo python3); $$PY -m pip install -q -r core/requirements.txt -c constraints.txt || $$PY -m pip install -q -r core/requirements.txt
	@PY=$$(command -v python3.11 || echo python3); $$PY tools/scripts/build_api_docs.py

.PHONY: netlify-link
netlify-link:
	@echo "[netlify] Linking repository to Netlify site (expects NETLIFY_TOKEN/NETLIFY_AUTH_TOKEN, optional NETLIFY_SITE_ID)"
	@set -a; [ -f .env ] && . .env || true; set +a; \
	  NETLIFY_AUTH_TOKEN=$${NETLIFY_AUTH_TOKEN:-$$NETLIFY_TOKEN} npx -y netlify-cli@17 link $${NETLIFY_SITE_ID:+--id=$$NETLIFY_SITE_ID}

.PHONY: api-docs-deploy
api-docs-deploy:
	@echo "[netlify] Deploying static API docs via Netlify build (using netlify.toml)"
	@set -a; [ -f .env ] && . .env || true; set +a; \
	  NETLIFY_AUTH_TOKEN=$${NETLIFY_AUTH_TOKEN:-$$NETLIFY_TOKEN} npx -y netlify-cli@17 deploy --build --prod $${NETLIFY_SITE_ID:+--site=$$NETLIFY_SITE_ID}

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	docker-compose down -v
