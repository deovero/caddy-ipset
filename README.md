# Caddy IPSet Matcher

Caddy HTTP matcher module that matches the client_ip against Linux ipset lists.

## Features

- **Native kernel communication** - Uses netlink to communicate directly with the Linux kernel
- Match HTTP requests against existing Linux ipset lists
- Uses Caddy's built-in client IP detection (respects `trusted_proxies` configuration)
- Automatic ipset validation on startup
- Comprehensive logging for debugging and monitoring
- Simple Caddyfile and JSON configuration
- High performance with minimal overhead
- Comprehensive unit tests

## How It Works

This module integrates with Caddy's request matcher system to check if a client's IP address is present in a specified Linux ipset.

The module uses the `vishvananda/netlink` library to communicate directly with the Linux kernel via netlink, providing native, high-performance ipset lookups without spawning external processes. This requires the CAP_NET_ADMIN capability.

## Requirements

- Linux system with ipset kernel module loaded
- Caddy v2
- CAP_NET_ADMIN capability (see [Permissions section](#permissions))

## Installation

### Using xcaddy

```bash
xcaddy build --with github.com/deovero/caddy-ipset
```

## Permissions

The module requires CAP_NET_ADMIN capability to access ipset via netlink.

### Grant CAP_NET_ADMIN capability

This enables direct netlink access for maximum performance:

```bash
sudo setcap cap_net_admin+ep ./caddy
```

**Advantages:**
- High performance (direct kernel communication)
- No process spawning overhead
- No additional configuration needed

**Note:** You can verify the capability is set with:
```bash
getcap ./caddy
```
should display
```text
./caddy cap_net_admin=ep
```

## Usage

### Caddyfile Configuration

Example:

```caddyfile
example.com {
	@matcher {
		ipset test-ipset-v4
		ipset test-ipset-v6
	}
	handle @matcher {
		respond "IP matches an ipset" 200
	}
	respond "IP does NOT match any of the ipsets" 403
}
```

When multiple ipset directives are used in a matcher block, Caddy creates multiple IpsetMatcher instances and ORs them together.
If want to be a tiny bit more efficient you can only try the ipset matching the protocol family:

```caddyfile
example.com {
    @blocked_v4 {
        not remote_ip ::/0  # Only IPv4
        ipset blocklist-v4 
    }
    @blocked_v6 {
        remote_ip ::/0  # Only IPv6
        ipset blocklist-v6
    }

    handle @blocked_v4 {
        respond "Access Denied" 403
    }
    handle @blocked_v6 {
        respond "Access Denied" 403
    }

    respond "Welcome!" 200
}
```

## Creating an IPSet

Before using this module, you need to create an ipset on your Linux system:

```bash
# Create a hash:net type ipset
sudo ipset create blocklist-v4 hash:net

# Add IPs to the set
sudo ipset add blocklist-v4 192.168.1.100
sudo ipset add blocklist-v4 10.0.0.50

# List the ipset
sudo ipset list blocklist-v4 
```

### Supported IPSet Types

This module works with various ipset types:
- `hash:net` - Network ranges (CIDR notation)
- `hash:ip` - Individual IP addresses (IPv4 or IPv6)
- Other hash types that support IP matching

To restore ipset on boot, add to `/etc/rc.local` or create a systemd service:

## Logging

The module provides detailed logging, examples:

- **Info**: When the module is provisioned
- **Debug**: When an IP is matched against the ipset, including the result
- **Error**: When there are issues parsing IPs or accessing ipset

## Testing

### Running Tests on Linux

```bash
go test -v
```

### Running Tests on macOS (Docker-based)

Since this module requires Linux kernel features (ipset), you can use Docker for testing on macOS:

#### Quick Start

```bash
# Run tests (builds image if needed)
make test

#### Available Make Commands

```bash
make help           # Show all available commands
make test           # Run tests in Docker container
make coverage       # Generate coverage.out file
make coverage-html  # Generate HTML coverage report (opens in browser)
make shell   # Open interactive shell in container
make clean          # Clean up Docker resources
```
For the full list of commands, run `make help`.

#### Manual Docker Usage

If you prefer to use Docker directly:

```bash
# Build the test image
docker-compose build

# Run tests
docker-compose run --rm caddy-ipset-test ./test-docker.sh

# Open interactive shell
docker-compose run --rm caddy-ipset-test /bin/bash
```

Inside the container, you can run tests manually:
```bash
# Run all tests
go test -v ./...

# Run with coverage
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Run specific test
go test -v -run TestProvision ./...

# Check ipset configuration
ipset list
```

### Testing the Module

To test if the module is working correctly:

1. Create a test ipset:
```bash
sudo ipset create test-ipset-v4 hash:net family inet
sudo ipset add test-ipset-v4 127.0.0.1
sudo ipset add test-ipset-v4 192.168.1.100
sudo ipset create test-ipset-v6 hash:net family inet6
sudo ipset add test-ipset-v6 ::1
```

2. Configure Caddy with the matcher:
Create this [Caddyfile](Caddyfile).

3. Execute Caddy:
```bash
./caddy run --config Caddyfile
```

4. Test with curl:
```bash
curl http://127.0.0.1:20080
# Should return "IPv4 is in the set"
curl http://[::1]:20080
# Should return "IPv6 is in the set"
curl http://127.0.0.1:20080 --header 'X-Forwarded-For: 192.168.1.100'
# Should return "IPv4 is in the set"
curl http://127.0.0.1:20080 --header 'X-Forwarded-For: 192.168.1.101'
# Should return "IP is NOT in the sets"
```

## Troubleshooting

### "ERROR ipset 'X' does not exist or cannot be accessed"

**Error message:**
```
Error: loading initial config: ... ERROR ipset 'test-ipset-v4' does not exist or cannot be accessed
```

**Cause**: The ipset list doesn't exist.

**Solution**:
1. Verify the ipset exists: `sudo ipset list -n <name>`
2. Create the ipset if it doesn't exist (see [Creating an IPSet](#creating-an-ipset) section)
3. Ensure the ipset name is spelled correctly in your configuration

### "ERROR invalid ipset name"

**Error message:**
```
Error: loading initial config: ... ERROR invalid ipset name 'my ipset': must contain only alphanumeric characters, hyphens, underscores, and dots
```

**Cause**: The ipset name contains invalid characters.

**Solution**: Ipset names must contain only alphanumeric characters, hyphens, underscores, and dots. Avoid spaces and special characters.

### Requests are being blocked/allowed incorrectly

**Cause**: IP address extraction might be incorrect, especially behind proxies.

**Solution**:
1. Check Caddy logs to see which IP is being tested
2. Configure `trusted_proxies` in your Caddyfile to extract the real client IP from proxy headers
3. Specify the IP ranges of the proxy servers:
   ```caddyfile
   {
       servers {
           trusted_proxies static 10.0.0.0/8 172.16.0.0/12
       }
   }
   ```

### "ERROR ipset 'X' cannot be accessed: permission denied"

**Error message:**
```
Error: loading initial config: ... ERROR ipset 'test-ipset-v4' cannot be accessed: permission denied. Grant CAP_NET_ADMIN capability with: sudo setcap cap_net_admin+ep ./caddy
```

**Cause**: Caddy doesn't have CAP_NET_ADMIN capability to access ipset via netlink.

**Solution**: Grant the capability to the Caddy binary:

```bash
sudo setcap cap_net_admin+ep /path/to/caddy
```

Then restart Caddy.

### "unknown ipset data attribute from kernel" messages

**Log messages:**
```
INFO    unknown ipset data attribute from kernel: {Type:21 Value:[12]} 21
INFO    unknown ipset data attribute from kernel: {Type:16401 Value:[241 100 79 57]} 17
```

**Cause**: The `vishvananda/netlink` library logs attributes it receives from the kernel but doesn't explicitly parse (such as CIDR2, MAC addresses, or other extended ipset attributes).

**Impact**: These are harmless informational messages. The ipset matcher works correctly - the library simply doesn't extract every possible attribute into its result structure.

**Solution**: No action needed. These messages can be safely ignored. If you want to suppress them, you can adjust your logging configuration to filter INFO level messages from the netlink library.

## License

Apache License 2.0 - see LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/deovero/caddy-ipset.git
cd caddy-ipset
```

2. Install the pre-commit hook (automatically formats Go code):
```bash
git  config  core.hooksPath  scripts
```

The pre-commit hook will:
- Automatically format all staged Go files using `gofmt -s`
- Run `go vet` to catch common mistakes
- Re-stage formatted files automatically
- Prevent commits if there are formatting or vet errors

### Running Tests

See the [Testing](#testing) section for detailed instructions on running tests locally using Docker.

## Authors

- [DeoVero](https://deovero.com) - [Jeroen Vermeulen](https://www.linkedin.com/in/jeroenvermeuleneu/)
- [Augment Code](https://www.augmentcode.com/)
