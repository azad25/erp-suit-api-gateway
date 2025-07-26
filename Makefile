# Django Core API Gateway Makefile

.PHONY: help install dev test clean build docker-build docker-run docker-stop migrate makemigrations shell superuser collectstatic lint format

# Variables
PYTHON = python3
PIP = pip3
MANAGE = python manage.py
DOCKER_COMPOSE = docker-compose

# Default target
help:
	@echo "Django Core API Gateway Commands:"
	@echo ""
	@echo "Development:"
	@echo "  install         - Install dependencies"
	@echo "  dev             - Run development server"
	@echo "  test            - Run tests"
	@echo "  clean           - Clean Python cache"
	@echo ""
	@echo "Database:"
	@echo "  migrate         - Run database migrations"
	@echo "  makemigrations  - Create new migrations"
	@echo "  shell           - Open Django shell"
	@echo "  superuser       - Create superuser"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-run      - Run with Docker Compose"
	@echo "  docker-stop     - Stop Docker containers"
	@echo ""
	@echo "Utilities:"
	@echo "  collectstatic   - Collect static files"
	@echo "  lint            - Run linting"
	@echo "  format          - Format code"

# Development Commands
install:
	@echo "Installing dependencies..."
	$(PIP) install -r requirements.txt
	@echo "✅ Dependencies installed"

dev:
	@echo "Starting development server..."
	$(MANAGE) runserver 0.0.0.0:8000

test:
	@echo "Running tests..."
	$(MANAGE) test --verbosity=2

clean:
	@echo "Cleaning Python cache..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	@echo "✅ Cleaned"

# Database Commands
migrate:
	@echo "Running migrations..."
	$(MANAGE) migrate

makemigrations:
	@echo "Creating migrations..."
	$(MANAGE) makemigrations

shell:
	@echo "Opening Django shell..."
	$(MANAGE) shell

superuser:
	@echo "Creating superuser..."
	$(MANAGE) createsuperuser

# Docker Commands
docker-build:
	@echo "Building Docker image..."
	$(DOCKER_COMPOSE) build

docker-run:
	@echo "Starting Docker containers..."
	$(DOCKER_COMPOSE) up -d

docker-stop:
	@echo "Stopping Docker containers..."
	$(DOCKER_COMPOSE) down

# Utility Commands
collectstatic:
	@echo "Collecting static files..."
	$(MANAGE) collectstatic --noinput

lint:
	@echo "Running linting..."
	flake8 .
	black --check .
	isort --check-only .

format:
	@echo "Formatting code..."
	black .
	isort .

# Setup Commands
setup: install migrate collectstatic
	@echo "✅ Setup complete"

setup-dev: install migrate collectstatic superuser
	@echo "✅ Development setup complete"

# Health Check
health:
	@echo "Checking service health..."
	curl -f http://localhost:8000/health/ || echo "❌ Service not healthy"

# Logs
logs:
	@echo "Showing logs..."
	$(DOCKER_COMPOSE) logs -f

# Reset
reset: docker-stop clean
	@echo "✅ Reset complete" 