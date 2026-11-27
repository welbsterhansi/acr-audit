.PHONY: help test lint format check all clean

help:
	@echo "Targets:"
	@echo "  make test     - roda pytest"
	@echo "  make lint     - roda ruff check"
	@echo "  make format   - aplica ruff format"
	@echo "  make check    - lint + test (CI local)"
	@echo "  make all      - format + check"
	@echo "  make clean    - remove caches"

test:
	python3 -m pytest

lint:
	ruff check .
	ruff format --check .

format:
	ruff format .
	ruff check --fix .

check: lint test

all: format check

clean:
	rm -rf .pytest_cache .ruff_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
