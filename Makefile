.PHONY: help docker-build docker-test docker-shell docker-clean docker-rebuild test-quick test-full

# Default target
help:
	@echo "Docker-based testing for caddy-ipset (macOS compatible)"
	@echo ""
	@echo "Available targets:"
	@echo "  make docker-build    - Build the Docker test image"
	@echo "  make docker-test     - Run tests in Docker container"
	@echo "  make test-quick      - Quick test (build + run tests)"
	@echo "  make test-full       - Full test suite with coverage"
	@echo "  make clean-full      - Clean first, then full test suite with coverage"
	@echo "  make docker-shell    - Open interactive shell in container"
	@echo "  make docker-clean    - Remove Docker containers and images"
	@echo "  make docker-rebuild  - Clean and rebuild everything"
	@echo ""
	@echo "Examples:"
	@echo "  make test-quick      # Fastest way to run tests"
	@echo "  make docker-shell    # Debug interactively"
	@echo ""
	@echo "Development targets:"
	@echo "  make install-hooks   - Install git pre-commit hook"
	@echo "  make format          - Format all Go files with gofmt"
	@echo "  make vet             - Run go vet on all files"

# Build the Docker image
docker-build:
	@echo "Building Docker test image..."
	docker-compose build

# Run tests in Docker container
docker-test:
	@echo "Running tests in Docker container..."
	docker-compose run --rm caddy-ipset-test /workspace/scripts/test-docker.sh

# Quick test - build and run
test-quick: docker-build docker-test

# Full test suite with detailed output
test-full: docker-build
	@echo "Running full test suite..."
	docker-compose run --rm caddy-ipset-test bash -c "\
		echo '=== Running go vet ===' && \
		go vet ./... && \
		echo '' && \
		echo '=== Running tests with coverage ===' && \
		go test -v -race -coverprofile=coverage.txt -covermode=atomic ./... && \
		echo '' && \
		echo '=== Coverage report ===' && \
		go tool cover -func=coverage.txt && \
		echo '' && \
		echo '=== Building module ===' && \
		go build -v ./..."

# Clean first, then full test suite with coverage
clean-full: docker-clean test-full

# Open interactive shell in container
docker-shell:
	@echo "Opening interactive shell in Docker container..."
	@echo "Run './scripts/test-docker.sh' inside the container to run tests"
	docker-compose run --rm caddy-ipset-test /bin/bash

# Clean up Docker resources
docker-clean:
	@echo "Cleaning up Docker resources..."
	docker-compose down -v
	docker rmi caddy-ipset-test 2>/dev/null || true

# Rebuild everything from scratch
docker-rebuild: docker-clean docker-build
	@echo "Rebuild complete!"

# Run specific test
test-specific:
	@echo "Running specific test (use TEST=TestName)..."
	docker-compose run --rm caddy-ipset-test go test -v -run $(TEST) ./...

# Check ipset status in container
check-ipset:
	@echo "Checking ipset configuration in container..."
	docker-compose run --rm caddy-ipset-test bash -c "ipset list -n && echo '' && ipset list"


# Development targets
.PHONY: install-hooks format vet

# Install git pre-commit hook

# Format all Go files
format:
	@echo "Formatting Go files..."
	@gofmt -s -w .
	@echo "✓ All Go files formatted"

# Run go vet
vet:
	@echo "Running go vet..."
	@if command -v go >/dev/null 2>&1; then \
		go vet ./... 2>/dev/null && echo "✓ go vet passed" || echo "Note: Run 'make test-quick' to run go vet in Docker"; \
	else \
		echo "Note: Go not found. Run 'make test-quick' to run go vet in Docker"; \
	fi
install-hooks:
	@echo "Installing pre-commit hook..."
	@cp hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "✓ Pre-commit hook installed"
	@echo "The hook will automatically format Go files and run go vet before each commit"

