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
	python3 -m pip install -q -r core/requirements.txt \
	  black==25.9.0 flake8==7.3.0 mypy==1.18.2 sqlalchemy==2.0.43 \
	  pytest pytest-cov pytest-asyncio

# Run the same checks as CI locally (fails on errors)
ci-local:
	black --check core/
	flake8 core/
	mypy --config-file mypy.ini core/
	PYTHONPATH=$$(pwd) pytest -q

proto:
	protoc -I=core/proto --python_out=core/proto core/proto/*.proto

docs:
	python -m pip install -q mkdocs mkdocs-material mike
	mkdocs build --strict

docs-serve:
	python -m pip install -q mkdocs mkdocs-material mike
	mkdocs serve --dev-addr=127.0.0.1:8000

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	docker-compose down -v
