.PHONY: help install test test-cov test-quick lint format clean build test-local

help: ## Show help information
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	poetry install

test: ## Run unit tests with coverage
	poetry run pytest tests/ -v --cov=cio_lambda_proxy --cov-report=term

test-cov: ## Run tests with coverage for CI
	poetry run pytest tests/ -v --cov=cio_lambda_proxy --cov-report=xml --cov-report=term

test-quick: ## Run quick tests without coverage
	poetry run pytest tests/ -v

lint: ## Check code quality
	poetry run flake8 cio_lambda_proxy/ tests/
	poetry run mypy cio_lambda_proxy/

format: ## Format code
	poetry run black cio_lambda_proxy/ tests/
	poetry run isort cio_lambda_proxy/ tests/

clean: ## Clean temporary files
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
	rm -rf .coverage coverage.xml htmlcov/ .pytest_cache/ .mypy_cache/ build/ lambda-package.zip

build: ## Build Lambda deployment package
	./build.sh

test-local: ## Test Lambda function locally
	@echo "🧪 Testing Lambda function locally..."
	@echo "1️⃣ Authorized request:"
	@python test_local.py authorized_request.json --skip-auth && echo "✅ PASSED" || echo "❌ FAILED"
	@echo ""
	@echo "2️⃣ Anonymous request:"
	@python test_local.py anonymous_request.json --skip-auth && echo "✅ PASSED" || echo "❌ FAILED"
	@echo ""
	@echo "ℹ️  For full unit tests run: make test"
