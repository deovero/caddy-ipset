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

# Check if ipsets are set up
echo -e "${YELLOW}Checking ipset setup...${NC}"
if ! ipset list -n &>/dev/null; then
    echo -e "${RED}Error: ipset not available. Make sure container is running with --privileged${NC}"
    exit 1
fi

echo -e "${YELLOW}Setting up test ipsets...${NC}"
/workspace/scripts/setup-test-ipsets.sh

# Run go vet
echo -e "${YELLOW}Running go vet...${NC}"
go vet ./...
echo -e "${GREEN}✓ go vet passed${NC}"
echo ""

# Build the test binary first with race detector and coverage
echo -e "${YELLOW}Building test binary with race detector and coverage...${NC}"
go test -c -race -cover -o /tmp/caddy-ipset.test
BUILD_EXIT_CODE=$?

if [ $BUILD_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Test binary built${NC}"
echo ""

# Run the tests as non-root user (testuser) twice:
#  - "effective": binary granted cap_net_admin=+ep, CAP_NET_ADMIN is effective on all threads
#  - "raise":     binary granted cap_net_admin=+p, the module raises CAP_NET_ADMIN per lookup
# Failures are collected so both modes always run.
TEST_EXIT_CODE=0
for MODE in effective raise; do
    if [ "$MODE" = "effective" ]; then CAPS="cap_net_admin=+ep"; else CAPS="cap_net_admin=+p"; fi
    echo -e "${YELLOW}Granting ${CAPS} to test binary...${NC}"
    setcap "$CAPS" /tmp/caddy-ipset.test
    getcap /tmp/caddy-ipset.test
    echo -e "${YELLOW}Running tests as non-root user (testuser) with ${CAPS}...${NC}"
    if su - testuser -c "cd /workspace && CADDY_IPSET_EXPECT_CAP_MODE=${MODE} /tmp/caddy-ipset.test -test.v -test.coverprofile=/tmp/coverage-${MODE}.out"; then
        echo -e "${GREEN}✓ Tests passed with ${CAPS}${NC}"
    else
        echo -e "${RED}✗ Tests failed with ${CAPS}${NC}"
        TEST_EXIT_CODE=1
    fi
    echo ""
done

# Merge the coverage profiles of both runs
if [ -f /tmp/coverage-effective.out ] && [ -f /tmp/coverage-raise.out ]; then
    { cat /tmp/coverage-effective.out; tail -n +2 /tmp/coverage-raise.out; } > coverage.out
fi

# Show coverage
if [ -f coverage.out ]; then
    echo -e "${YELLOW}Test coverage:${NC}"
    go tool cover -func=coverage.out | tail -n 1
    echo ""
fi

# Build the module
echo -e "${YELLOW}Building module...${NC}"
go build -v .
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
if [ $TEST_EXIT_CODE -eq 0 ] && [ $BUILD_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi

