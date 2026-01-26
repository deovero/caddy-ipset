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

echo -e "${YELLOW}Setting up test ipsets...${NC}"
/workspace/scripts/setup-test-ipsets.sh

echo -e "${YELLOW}Running benchmarks...${NC}"
go test -bench=. -benchmem -v | grep '^Benchmark' | tee results/benchmark.txt
BUILD_EXIT_CODE=$?

echo ""
if [ $BUILD_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Benchmarks completed${NC}"
else
    echo -e "${RED}✗ Benchmarks failed${NC}"
fi
echo ""
