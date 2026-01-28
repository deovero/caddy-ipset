.PHONY: help test format vet clean build rebuild shell clean-full test-specific coverage coverage-html check-ipset docker-test

# Default target
help:
	@echo "Docker-based testing for caddy-ipset (macOS compatible)"
	@echo ""
	@echo "Available targets:"
	@echo "  make test              - Run tests in Docker container"
	@echo "  make bench             - Run benchmarks in Docker container"
	@echo "  make format            - Format all Go files with gofmt"
	@echo "  make vet               - Run go vet on all files"
	@echo "  make clean             - Remove Docker containers and images"
	@echo "  make build             - Build the Docker test image"
	@echo "  make rebuild           - Clean and rebuild everything"
	@echo "  make shell             - Open interactive Docker shell in container"
	@echo "  make test-specific     - Run specific test (use TEST=TestName)"
	@echo "  make coverage          - Generate coverage.out file"
	@echo "  make coverage-html     - Generate HTML coverage report (opens in browser)"

# Build the Docker image
build:
	@echo "Building Docker test image..."
	docker-compose build

# Run tests in Docker container
test:
	@echo "Running tests in Docker container..."
	docker-compose run --rm caddy-ipset-test /workspace/scripts/test-docker.sh

# Run benchmarks in Docker container
bench:
	@echo "Running benchmarks in Docker container..."
	docker-compose run --rm caddy-ipset-test /workspace/scripts/benchmark-docker.sh

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
	docker rmi caddy-ipset-caddy-ipset-test 2>/dev/null || true

# Rebuild everything from scratch
rebuild: clean build
	@echo "Rebuild complete!"

# Run specific test
test-specific:
	@echo "Running specific test (use TEST=TestName)..."
	docker-compose run --rm caddy-ipset-test go test -v -run $(TEST) ./...

# Generate coverage for IntelliJ/GoLand
coverage:
	@echo "Generating coverage report..."
	docker-compose run --rm caddy-ipset-test bash -c "\
	    /workspace/scripts/setup-test-ipsets.sh && \
		go test -coverprofile=coverage.out -covermode=atomic ./... && \
		echo '' && \
		echo '✓ Coverage file generated: coverage.out' && \
		echo '' && \
		go tool cover -func=coverage.out"

# Generate HTML coverage report and open in browser
coverage-html:
	@echo "Generating HTML coverage report..."
	@docker-compose run --rm caddy-ipset-test bash -c "\
	    /workspace/scripts/setup-test-ipsets.sh && \
		go test -coverprofile=coverage.out -covermode=atomic ./... && \
		go tool cover -html=coverage.out -o coverage.html && \
		echo '' && \
		echo '✓ Coverage HTML report generated: coverage.html' && \
		echo '' && \
		go tool cover -func=coverage.out"
	@echo ""
	@echo "Opening coverage report in browser..."
	@open coverage.html 2>/dev/null || xdg-open coverage.html 2>/dev/null || echo "Please open coverage.html in your browser"

# Format all Go files
format:
	@echo "Formatting Go files..."
	@gofmt -s -w .
	@echo "✓ All Go files formatted"

# Run go vet
vet:
	@echo "Running go vet in Docker container..."
	docker-compose run --rm caddy-ipset-test bash -c "\
	    go vet ./... && \
	    echo '✓ go vet completed successfully'"