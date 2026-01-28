# Caddy IPSet Matcher

Caddy HTTP matcher module that matches the client_ip against Linux ipset lists using native netlink communication.
This enables efficient filtering against large, dynamic sets of IPs and CIDR ranges.

## Features

- High performance with minimal overhead
- Match HTTP requests against existing Linux ipset lists
- Uses Caddy's built-in client IP detection (respects `trusted_proxies` configuration)
- Automatic validation of ipset configuration on startup
- Comprehensive logging for debugging and monitoring
- Simple Caddyfile configuration
- Comprehensive unit tests
- Prometheus metrics for observability

## Prometheus Metrics

The module exposes the following Prometheus metrics for monitoring and observability:

| Metric | Type | Labels | Description                                                              |
|--------|------|--------|--------------------------------------------------------------------------|
| `caddy_http_matchers_ipset_module_instances` | Gauge | - | Number of ipset matcher module instances currently loaded                |
| `caddy_http_matchers_ipset_requests_total` | Counter | - | Total number of requests processed by the ipset matcher                  |
| `caddy_http_matchers_ipset_results_total` | Counter | `ipset`, `result` | IPset membership tests by ipset name and result (`found` or `not_found`) |
| `caddy_http_matchers_ipset_test_duration_seconds` | Histogram | `ipset` | Duration of ipset netlink tests by ipset name                            |
| `caddy_http_matchers_ipset_netlink_handles_open` | Gauge | - | Number of netlink handles currently open for ipset tests                 |
| `caddy_http_matchers_ipset_errors_total` | Counter | `error_type` | Total number of errors during ipset tests by error type                  |

These metrics are automatically exposed via Caddy's admin API when the Prometheus metrics endpoint is enabled:

```caddyfile
{
    admin :2019
}
```

Metrics are then available at `http://localhost:2019/metrics`.

## How It Works

This module integrates with Caddy's request matcher system to test if a client's IP address is present in a specified Linux ipset.

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
sudo setcap cap_net_admin+ep /path/to/caddy
```

**Advantages:**
- High performance (direct kernel communication)
- No process spawning overhead
- No additional configuration needed

**Note:** You can verify the capability is set with:
```bash
getcap /path/to/caddy
```
should display
```text
/path/to/caddy cap_net_admin=ep
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
If you want to be a tiny bit more efficient you can only try the ipset matching the protocol family:

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
- `hash:ip` - Individual IP addresses
- Other hash types that support IP matching

### Supported IPSet Families

This module works with both IP families:
- `inet` - IPv4
- `inet6` - IPv6

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
make bench          # Run benchmarks in Docker container
make coverage       # Generate coverage.out file
make coverage-html  # Generate HTML coverage report (opens in browser)
make shell   # Open interactive shell in container
make clean          # Clean up Docker resources
```
For the full list of commands, run `make help`.

## Troubleshooting

### "CAP_NET_ADMIN capability required"

**Error message:**
```
Error: loading matcher modules: module name 'ipset': provision http.matchers.ipset: CAP_NET_ADMIN capability required. Grant with: sudo setcap cap_net_admin+ep /path/to/caddy
```

**Cause**: The Caddy binary doesn't have the required CAP_NET_ADMIN capability to access ipset via netlink.

**Solution**:
1. Grant the capability to your Caddy binary:
   ```bash
   sudo setcap cap_net_admin+ep /path/to/your/caddy
   ```
2. Verify the capability is set:
   ```bash
   getcap ./caddy
   # Should display: ./caddy cap_net_admin=ep
   ```
3. **Important**: If you replace or rebuild the Caddy binary, you'll need to grant the capability again.

### "no such file or directory" during provision of ipset

**Error message:**
```
Error: ... loading matcher modules: module name 'ipset': provision http.matchers.ipset: error validating ipset 'X': no such file or directory
```

**Cause**: The ipset list doesn't exist or Caddy cannot access it.

**Solution**:
1. Verify the ipset exists:
   ```bash
   sudo ipset list -n
   # Or check a specific ipset:
   sudo ipset list test-ipset-v4
   ```
2. Create the ipset if it doesn't exist (see [Creating an IPSet](#creating-an-ipset) section)
3. Ensure the ipset name is spelled correctly in your configuration

### "operation not permitted" during provision of ipset

**Error message:**
```
Error: ... loading matcher modules: module name 'ipset': provision http.matchers.ipset: error validating ipset 'X': operation not permitted
```

**Cause**: Caddy can't access the ipset due to insufficient permissions or systemd sandboxing.

**Solution**:

**Option 1: Check CAP_NET_ADMIN capability**
```bash
getcap /path/to/caddy
# Should show: /path/to/caddy cap_net_admin=ep
```

**Option 2: Adjust systemd service restrictions**

When running Caddy as a systemd service, certain sandboxing options can prevent netlink access. Edit your systemd service file (e.g., `/etc/systemd/system/caddy.service`):

```ini
[Service]
# These settings may interfere with netlink access:
# PrivateTmp=true          # Can cause issues
# ProtectSystem=strict     # Can cause issues
# ProtectHome=true         # Usually OK
```

After modifying the service file:
```bash
sudo systemctl daemon-reload
sudo systemctl restart caddy
```

### "ipset name exceeds maximum length"

**Error message:**
```
Error: ... ipset name 'very-long-name...' exceeds maximum length of 31 characters
```

**Cause**: Ipset names are limited to 31 characters by the Linux kernel.

**Solution**: Use a shorter ipset name (31 characters or less).

### "at least one ipset name is required"

**Error message:**
```
Error: ... at least one ipset name is required
```

**Cause**: The ipset matcher is configured without any ipset names.

**Solution**: Add at least one ipset name to your configuration:
```caddyfile
@blocked {
    ipset blocklist-v4
}
```

### Requests are being blocked/allowed incorrectly

**Cause**: IP address extraction might be incorrect, especially when behind proxies or load balancers.

**Solution**:
1. Enable debug logging to see which IP is being tested:
   ```caddyfile
   {
       log {
           level DEBUG
       }
   }
   ```
2. Check the logs for messages like:
   ```
   Tested IP against ipset {"clientIp": "192.168.1.100", "ipset": "test-ipset-v4", "result": "found"}
   ```
3. Configure `trusted_proxies` to extract the real client IP from proxy headers:
   ```caddyfile
   {
       servers {
           trusted_proxies static 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
       }
   }
   
   ```
4. Verify your ipset contains the expected IPs:
   ```bash
   sudo ipset list blocklist-v4
   ```

### IPv4/IPv6 matching issues

**Symptom**: IPv4 addresses aren't matching against your ipset, or vice versa for IPv6.

**Cause**: IP family mismatch between the client IP and the ipset type.

**Solution**:
1. Verify your ipset family:
   ```bash
   sudo ipset list blocklist-v4 | grep "Type:"
   # Should show: Type: hash:net family inet
   ```
2. Create separate ipsets for IPv4 and IPv6:
   ```bash
   sudo ipset create blocklist-v4 hash:net family inet
   sudo ipset create blocklist-v6 hash:net family inet6
   ```
3. Configure both in your Caddyfile:
   ```caddyfile
   @blocked {
       ipset blocklist-v4
       ipset blocklist-v6
   }
   ```

The module automatically skips mismatched IP families (you'll see debug messages like "skipped matching of IPv6 address against IPv4 ipset").

### "unknown ipset data attribute from kernel" messages

**Log messages:**
```
INFO    unknown ipset data attribute from kernel: {Type:21 Value:[12]} 21
INFO    unknown ipset data attribute from kernel: {Type:16401 Value:[241 100 79 57]} 17
```

**Cause**: The `vishvananda/netlink` library logs attributes it receives from the kernel but doesn't explicitly parse (such as CIDR2, MAC addresses, or other extended ipset attributes).

**Impact**: These are harmless informational messages. The ipset matcher works correctly - the library simply doesn't extract every possible attribute into its result structure.

**Solution**: No action needed. These messages can be safely ignored. If you want to suppress them, you can adjust your logging configuration to filter INFO level messages from the netlink library.

### "failed to create netlink handle"

**Error message:**
```
Error: ... failed to create netlink handle: ...
```

**Cause**: Unable to create a netlink socket for communication with the kernel.

**Solution**:
1. Verify the ipset kernel module is loaded:
   ```bash
   lsmod | grep ip_set
   # If not loaded:
   sudo modprobe ip_set
   ```
2. Check system limits for file descriptors:
   ```bash
   ulimit -n
   # Increase if needed:
   ulimit -n 4096
   ```
3. Ensure CAP_NET_ADMIN capability is granted (see first troubleshooting section)

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