SHELL := /bin/bash
.PHONY: dev test lint typecheck docker docker-build docker-up docker-down clean

dev:
	pip install -e ".[dev]"
	cd web && npm install

test:
	pytest -v --tb=short

lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy core/ parsers/ api/ cli/ report/

docker-build:
	docker compose build

docker-up:
	docker compose up

docker-down:
	docker compose down

docker: docker-build docker-up

clean:
	rm -rf *.egg-info dist build __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf data/fw-insight.db
	cd web && rm -rf node_modules dist
