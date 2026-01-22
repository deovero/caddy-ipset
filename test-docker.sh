#!/bin/bash
# Script to run tests inside Docker container

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running inside Docker container
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && ! grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo -e "${RED}Error: This script must be run inside a Docker container${NC}"
    echo -e "${YELLOW}Please use the appropriate Docker command to run tests${NC}"
    exit 1
fi

echo "========================================="
echo "Running tests in Docker container"
echo "========================================="
echo ""

# Check if ipsets are set up
echo -e "${YELLOW}Checking ipset setup...${NC}"
if ! ipset list -n &>/dev/null; then
    echo -e "${RED}Error: ipset not available. Make sure container is running with --privileged${NC}"
    exit 1
fi

echo -e "${GREEN}Available ipsets:${NC}"
ipset list -n
echo ""

# Run go vet
echo -e "${YELLOW}Running go vet...${NC}"
go vet ./...
echo -e "${GREEN}✓ go vet passed${NC}"
echo ""

# Run tests with different permission levels
echo -e "${YELLOW}Running tests as root (netlink access)...${NC}"
go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Tests passed as root${NC}"
else
    echo -e "${RED}✗ Tests failed as root${NC}"
fi
echo ""

# Show coverage
if [ -f coverage.txt ]; then
    echo -e "${YELLOW}Test coverage:${NC}"
    go tool cover -func=coverage.txt | tail -n 1
    echo ""
fi

# Test as non-root user (sudo fallback)
echo -e "${YELLOW}Running tests as non-root user (sudo fallback)...${NC}"
su - testuser -c "cd /workspace && go test -v ./..."
SUDO_TEST_EXIT_CODE=$?

if [ $SUDO_TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Tests passed as non-root user${NC}"
else
    echo -e "${RED}✗ Tests failed as non-root user${NC}"
fi
echo ""

# Build the module
echo -e "${YELLOW}Building module...${NC}"
go build -v ./...
BUILD_EXIT_CODE=$?

if [ $BUILD_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
fi
echo ""

# Summary
echo "========================================="
echo "Test Summary"
echo "========================================="
if [ $TEST_EXIT_CODE -eq 0 ] && [ $SUDO_TEST_EXIT_CODE -eq 0 ] && [ $BUILD_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi

