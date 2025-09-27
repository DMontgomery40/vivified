.PHONY: help build up down test lint proto clean

help:
	@echo "Available commands:"
	@echo "  make build   - Build all Docker images"
	@echo "  make up      - Start all services"
	@echo "  make down    - Stop all services"
	@echo "  make test    - Run tests"
	@echo "  make lint    - Run linters"
	@echo "  make proto   - Compile protobuf files"
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

proto:
	protoc -I=core/proto --python_out=core/proto core/proto/*.proto

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	docker-compose down -v
