.PHONY: install test coverage lint fmt typecheck check worker api docker-up docker-down migrate clean

install:
	pip install -e ".[dev,all]"

test:
	pytest tests/unit/ -v --tb=short

coverage:
	pytest tests/unit/ --cov=redgnat --cov-report=html --cov-report=term-missing

integration:
	pytest tests/integration/ --run-integration -v

lint:
	ruff check redgnat/ tests/
	ruff format --check redgnat/ tests/

fmt:
	ruff format redgnat/ tests/
	ruff check --fix redgnat/ tests/

typecheck:
	mypy redgnat/

check: lint typecheck

worker:
	celery -A redgnat.emulation.tasks worker --loglevel=info -Q redgnat

beat:
	celery -A redgnat.emulation.tasks beat --loglevel=info

api:
	uvicorn redgnat.api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload

docker-up:
	docker compose up -d

docker-down:
	docker compose down

migrate:
	@for f in migrations/*.sql; do \
		echo "Applying $$f ..."; \
		psql "$$REDGNAT_DB_URL" -f "$$f"; \
	done

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -type f -name "*.pyc" -delete 2>/dev/null; true
	rm -rf .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info
