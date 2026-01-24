# Docker-Based Testing for macOS

This guide explains how to test the caddy-ipset module on macOS using Docker.

## Why Docker?

The caddy-ipset module requires Linux-specific features:
- Linux kernel ipset module
- Netlink communication with the kernel
- Linux-specific syscalls

Docker provides a Linux environment on macOS, allowing you to develop and test the module locally.

## Prerequisites

- Docker Desktop for Mac installed and running
- Make (comes with Xcode Command Line Tools)

## Quick Start

The easiest way to run tests:

```bash
make test
```

This will:
1. Build the Docker image (if not already built)
2. Start a privileged container with ipset support
3. Run the full test suite
4. Show test results and coverage

## Available Commands

### Testing Commands

```bash
# Quick test (recommended for development)
make test

# Full test suite with detailed coverage
make test

# Run specific test
make test-specific TEST=TestProvision

# Check ipset configuration
make check-ipset
```

### Docker Management

```bash
# Build the Docker image
make build

# Open interactive shell in container
make shell

# Clean up Docker resources
make clean

# Rebuild everything from scratch
make rebuild

# Show all available commands
make help
```

## Interactive Development

For debugging or manual testing, open an interactive shell:

```bash
make shell
```

Inside the container, you can:

```bash
# Run tests
go test -v ./...

# Run tests with race detection
go test -v -race ./...

# Run specific test
go test -v -run TestMatch ./...

# Check ipset lists
ipset list

# Add test IPs to ipset
ipset add test-ipset-v4 192.168.1.100

# Build caddy with the module
pkill caddy
rm -f ./caddy
xcaddy build --with github.com/deovero/caddy-ipset=/workspace
./caddy run & sleep 2
echo -e "\n\nShould match:"
curl http://127.0.0.1:20080
echo -e "\n\nShould match:"
curl http://[::1]:20080
echo -e "\n\nShould NOT match:"
curl http://127.0.0.1:20080 --header 'X-Forwarded-For: 192.168.1.1'
echo -e "\n\nShould match:"
curl http://127.0.0.1:20080 --header 'X-Forwarded-For: 192.168.1.100'
echo -e "\n"
for i in $(seq 1 10000); do curl -s -o /dev/null http://127.0.0.1:20080; done
pkill caddy
```

## How It Works

### Docker Setup

1. **scripts/Dockerfile**: Creates an Ubuntu 24.04 container with:
   - Go 1.25
   - ipset and iptables
   - libcap2-bin for setcap support
   - Test ipsets pre-configured
   - Non-root testuser for realistic testing

2. **docker-compose.yml**: Manages the container with:
   - Privileged mode (required for ipset kernel module)
   - Volume mounts for live code editing
   - Go module cache persistence

3. **test-docker.sh**: Automated test script that:
   - Verifies ipset setup
   - Builds test binary and grants CAP_NET_ADMIN capability with setcap
   - Runs tests as non-root user (testuser) with CAP_NET_ADMIN
   - Generates coverage reports

### Test Ipsets

The container automatically creates these test ipsets:

- `test-ipset-v4`: Contains 127.0.0.1, 192.168.1.100 (IPv4)
- `test-ipset-v6`: Contains ::1, 2001:db8::1, fe80::1 (IPv6)
- `blocklist-v4`: Contains 10.0.0.1 (IPv4)
- `blocklist-v6`: Contains 2001:db8::bad (IPv6)
- `empty-v4`: Empty (IPv4, for testing)
- `empty-v6`: Empty (IPv6, for testing)

## Troubleshooting

### "Cannot load ipset module"

**Solution**: Make sure Docker Desktop is running and the container has privileged mode enabled (already configured in docker-compose.yml).

### "Permission denied" when running make

**Solution**: Ensure the test-docker.sh script is executable:
```bash
chmod +x test-docker.sh
```

### Tests fail with "ipset does not exist"

**Solution**: The container's entrypoint should automatically create test ipsets. If not, run manually:
```bash
make shell
# Inside container:
/usr/local/bin/setup-ipsets.sh
```

### Slow Docker builds

**Solution**: The scripts/Dockerfile uses layer caching. If you need to rebuild:
```bash
make rebuild
```

### Changes not reflected in tests

The source code is mounted as a volume, so changes are immediately available. Just run tests again:
```bash
make docker-test
```

## CI/CD Integration

The GitHub Actions workflow runs on Ubuntu and doesn't need Docker. The Docker setup is specifically for local macOS development.

## Performance Notes

- First build takes 2-3 minutes (downloads Go, installs packages)
- Subsequent builds are fast (uses Docker layer caching)
- Tests run at near-native speed
- Go module cache is persisted in a Docker volume

## Cleaning Up

To free up disk space:

```bash
# Remove containers and volumes
make clean

# Remove everything including images
docker-compose down -v --rmi all
```

## Tips

1. **Keep the container running**: Use `make shell` and run multiple test commands without rebuilding
2. **Watch mode**: Use a file watcher on macOS to automatically run tests when files change
3. **Coverage reports**: Coverage files are written to the mounted volume and accessible on macOS
4. **Debugging**: Add `fmt.Println()` or use `t.Logf()` in tests - output is visible in real-time

