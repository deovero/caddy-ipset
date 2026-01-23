# Caddy IPSet Matcher

A Caddy HTTP matcher module that matches requests based on client IP addresses against Linux ipset lists.

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

Block requests from IPs in an ipset:

```caddyfile
example.com {
    @blocked {
        ipset fail2ban-blocklist
    }

    handle @blocked {
        respond "Access Denied" 403
    }

    respond "Welcome!" 200
}
```

Allow only IPs in an ipset:

```caddyfile
admin.example.com {
    @allowed {
        ipset trusted-ips
    }

    handle @allowed {
        reverse_proxy localhost:8080
    }

    respond "Unauthorized" 401
}
```

#### Using with Trusted Proxies

When behind a proxy (like Cloudflare, nginx, or a load balancer), configure `trusted_proxies` to get the real client IP:

```caddyfile
{
    servers {
        trusted_proxies static 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22
    }
}

example.com {
    @blocked {
        ipset fail2ban-blocklist
    }

    handle @blocked {
        respond "Access Denied" 403
    }

    respond "Welcome!" 200
}
```

### JSON Configuration

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "routes": [
            {
              "match": [
                {
                  "ipset": "fail2ban-blocklist"
                }
              ],
              "handle": [
                {
                  "handler": "static_response",
                  "status_code": 403,
                  "body": "Access Denied"
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

## Creating an IPSet

Before using this module, you need to create an ipset on your Linux system:

```bash
# Create a hash:ip type ipset
sudo ipset create fail2ban-blocklist hash:ip

# Add IPs to the set
sudo ipset add fail2ban-blocklist 192.168.1.100
sudo ipset add fail2ban-blocklist 10.0.0.50

# List the ipset
sudo ipset list fail2ban-blocklist

# Save ipset (persist across reboots)
sudo ipset save > /etc/ipset.conf
```

### Supported IPSet Types

This module works with various ipset types:
- `hash:ip` - Individual IP addresses (IPv4 or IPv6)
- `hash:net` - Network ranges (CIDR notation)
- Other hash types that support IP matching

To restore ipset on boot, add to `/etc/rc.local` or create a systemd service:

```bash
sudo ipset restore < /etc/ipset.conf
```

## Integration with Fail2Ban

This plugin works great with Fail2Ban. Configure Fail2Ban to use ipset:

```ini
# /etc/fail2ban/jail.local
[DEFAULT]
banaction = iptables-ipset-proto4

[caddy-auth]
enabled = true
port = http,https
filter = caddy-auth
logpath = /var/log/caddy/access.log
maxretry = 5
bantime = 3600
```

## Logging

The module provides detailed logging:

- **Info**:
  - When the module is provisioned
  - When an IP matches the ipset
- **Debug**: When an IP is not in the ipset
- **Error**: When there are issues parsing IPs or accessing ipset

Example log output:
```
INFO ipset matcher provisioned using netlink {"ipset": "blocklist"}
```

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
make test-quick

# Or run full test suite with coverage
make test-full
```

#### Available Make Commands

```bash
make help           # Show all available commands
make docker-build   # Build the Docker test image
make docker-test    # Run tests in Docker container
make coverage       # Generate coverage.out file
make coverage-html  # Generate HTML coverage report (opens in browser)
make docker-shell   # Open interactive shell in container
make docker-clean   # Clean up Docker resources
make check-ipset    # Check ipset configuration in container
```

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
sudo ipset create test-v4 hash:net family inet
sudo ipset add test-v4 127.0.0.1
sudo ipset create test-v6 hash:net family inet6
sudo ipset add test-v6 ::1
```

2. Configure Caddy with the matcher:
Create this `Caddyfile` in the directory of the `caddy` binary:
```caddyfile
{
	admin off
	log {
		level DEBUG
	}
}
:20080 {
	@match_v4 {
		not remote_ip ::/0
		ipset test-v4
	}
	@match_v6 {
		remote_ip ::/0
		ipset test-v6
	}
	handle @match_v4 {
		respond "IPv4 is in the set!" 200
	}
	handle @match_v6 {
		respond "IPv6 is in the set!" 200
	}
	respond "IP is NOT in the sets" 200
}
```

3. Execute Caddy:
```bash
./caddy run
```

4. Test with curl:
```bash
curl -4 http://localhost:20080
# Should return "IPv4 is in the set!" if your IP is 127.0.0.1
curl -6 http://localhost:20080
# Should return "IPv6 is in the set!" if your IP is ::1
```

## Troubleshooting

### "ipset does not exist or cannot be accessed"

**Cause**: The ipset list doesn't exist or Caddy doesn't have permission to access it.

**Solution**:
1. Verify the ipset exists: `sudo ipset list -n <name>`
2. Check Caddy has the necessary permissions (see Permissions section)
3. Ensure the ipset name is spelled correctly in your configuration

### "invalid ipset name"

**Cause**: The ipset name contains invalid characters.

**Solution**: Ipset names must contain only alphanumeric characters, hyphens, underscores, and dots. Avoid spaces and special characters.

### Requests are being blocked/allowed incorrectly

**Cause**: IP address extraction might be incorrect, especially behind proxies.

**Solution**:
1. Check Caddy logs to see which IP is being tested
2. Configure `trusted_proxies` in your Caddyfile to extract the real client IP from proxy headers
3. Example for Cloudflare:
   ```caddyfile
   {
       servers {
           trusted_proxies static cloudflare
       }
   }
   ```
4. For custom proxies, specify their IP ranges:
   ```caddyfile
   {
       servers {
           trusted_proxies static 10.0.0.0/8 172.16.0.0/12
       }
   }
   ```

### "operation not permitted" error

**Error message:**
```
Error: loading initial config: ... ipset 'test-ipset' cannot be accessed: permission denied
```

**Cause**: Caddy doesn't have CAP_NET_ADMIN capability to access netlink.

**Solution**: Grant the capability to the Caddy binary:

```bash
sudo setcap cap_net_admin+ep /path/to/caddy
```

Then restart Caddy.

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

### Manual Formatting

If you want to format files manually without committing:

```bash
# Format all Go files
gofmt -s -w .

# Run go vet
go vet ./...
```

### Running Tests

See the [Testing](#testing) section for detailed instructions on running tests locally using Docker.

## Authors

- [DeoVero](https://deovero.com) - [Jeroen Vermeulen](https://www.linkedin.com/in/jeroenvermeuleneu/)
- [Augment Code](https://www.augmentcode.com/)
