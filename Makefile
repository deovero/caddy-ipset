.PHONY: help test format vet clean build rebuild shell clean-full test-specific coverage coverage-html check-ipset docker-test

# Default target
help:
	@echo "Docker-based testing for caddy-ipset (macOS compatible)"
	@echo ""
	@echo "Available targets:"
	@echo "  make test              - Build + run docker-test"
	@echo "  make bench             - Build + run docker-bench"
	@echo "  make format            - Format all Go files with gofmt"
	@echo "  make vet               - Run go vet on all files"
	@echo "  make clean             - Remove Docker containers and images"
	@echo "  make build             - Build the Docker test image"
	@echo "  make rebuild           - Clean and rebuild everything"
	@echo "  make shell             - Open interactive Docker shell in container"
	@echo "  make clean-test        - Clean first, then test"
	@echo "  make test-specific     - Run specific test (use TEST=TestName)"
	@echo "  make coverage          - Generate coverage.out file"
	@echo "  make coverage-html     - Generate HTML coverage report (opens in browser)"
	@echo "  make check-ipset       - Check ipset configuration in container"
	@echo "  make docker-test       - Run tests in Docker container"
	@echo "  make docker-bench      - Run benchmarks in Docker container"

# Build the Docker image
build:
	@echo "Building Docker test image..."
	docker-compose build

# Run tests in Docker container
docker-test:
	@echo "Running tests in Docker container..."
	docker-compose run --rm caddy-ipset-test /workspace/scripts/test-docker.sh

# Test - build and run
test: build docker-test

# Run benchmarks in Docker container
docker-bench:
	@echo "Running benchmarks in Docker container..."
	docker-compose run --rm caddy-ipset-test /workspace/scripts/benchmark-docker.sh

# Benchmark - build and run
bench: build docker-bench

# Clean first, then test
clean-test: clean test

# Open interactive shell in container
shell:
	@echo "Opening interactive shell in Docker container..."
	@echo "Run './scripts/test-docker.sh' inside the container to run tests"
	docker-compose run --rm caddy-ipset-test /bin/bash

# Clean up Docker resources
clean:
	@echo "Cleaning up Docker resources..."
	docker-compose down -v
	docker rmi caddy-ipset-test 2>/dev/null || true

# Rebuild everything from scratch
rebuild: clean build
	@echo "Rebuild complete!"

# Run specific test
test-specific:
	@echo "Running specific test (use TEST=TestName)..."
	docker-compose run --rm caddy-ipset-test go test -v -run $(TEST) ./...

# Check ipset status in container
check-ipset:
	@echo "Checking ipset configuration in container..."
	docker-compose run --rm caddy-ipset-test bash -capSet "ipset list -n && echo '' && ipset list"

# Generate coverage for IntelliJ/GoLand
coverage:
	@echo "Generating coverage report..."
	docker-compose run --rm caddy-ipset-test bash -capSet "\
		go test -coverprofile=coverage.out -covermode=atomic ./... && \
		echo '' && \
		echo '✓ Coverage file generated: coverage.out' && \
		echo '' && \
		go tool cover -func=coverage.out"

# Generate HTML coverage report and open in browser
coverage-html:
	@echo "Generating HTML coverage report..."
	@docker-compose run --rm caddy-ipset-test bash -capSet "\
		go test -coverprofile=coverage.out -covermode=atomic ./... && \
		go tool cover -html=coverage.out -o coverage.html && \
		echo '' && \
		echo '✓ Coverage HTML report generated: coverage.html' && \
		echo '' && \
		go tool cover -func=coverage.out"
	@echo ""
	@echo "Opening coverage report in browser..."
	@open coverage.html 2>/dev/null || xdg-open coverage.html 2>/dev/null || echo "Please open coverage.html in your browser"

# Development targets
.PHONY: format vet

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
		go vet ./... 2>/dev/null && echo "✓ go vet passed" || echo "Note: Run 'make test' to run go vet in Docker"; \
	else \
		echo "Note: Go not found. Run 'make test' to run go vet in Docker"; \
	fi
