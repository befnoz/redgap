# RedGap — developer entry points. The default path needs no Docker and no API key.
.DEFAULT_GOAL := help
.PHONY: help install demo live lab-up lab-down capture test lint fmt

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

install: ## Editable install with dev + llm extras
	python -m pip install -e ".[dev,llm]"

demo: ## Default: run the coverage loop in REPLAY (offline, no key, no Docker)
	redgap run

live: ## Run against the disposable Docker lab (requires Docker)
	redgap run --live

lab-up: ## Bring up the disposable lab
	redgap lab up

lab-down: ## Tear the lab down and remove volumes
	redgap lab down -v

capture: ## Regenerate the real-telemetry replay fixtures from a live run
	redgap capture

test: ## Run the test suite
	python -m pytest

lint: ## Lint + format-check
	ruff check .
	ruff format --check .

fmt: ## Auto-format
	ruff check --fix .
	ruff format .
