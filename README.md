# Caddy IPSet Matcher

A Caddy HTTP matcher module that matches requests based on client IP addresses against Linux ipset lists.

## Features

- **Native kernel communication** - Uses netlink to communicate directly with the Linux kernel (no shell commands)
- **Automatic fallback** - Falls back to `sudo ipset` when running as non-privileged user
- Match HTTP requests against existing Linux ipset lists
- Uses Caddy's built-in client IP detection (respects `trusted_proxies` configuration)
- Automatic support for X-Forwarded-For, X-Real-IP, Cf-Connecting-IP headers via `trusted_proxies`
- Automatic ipset validation on startup
- Comprehensive logging for debugging and monitoring
- Simple Caddyfile and JSON configuration
- High performance with minimal overhead
- Comprehensive unit tests

## How It Works

This module integrates with Caddy's request matcher system to check if a client's IP address is present in a specified Linux ipset.

**Access Methods:**
1. **Netlink (preferred)** - Uses the `vishvananda/netlink` library to communicate directly with the Linux kernel via netlink, providing native, high-performance ipset lookups without spawning external processes. Requires CAP_NET_ADMIN capability.
2. **Sudo fallback** - If netlink access is denied (permission error), automatically falls back to using `sudo ipset` commands. This allows the module to work when Caddy runs as a non-privileged user.

The module automatically detects which method to use during provisioning and logs the selected method.

## Requirements

- Linux system with ipset kernel module loaded
- Caddy v2
- **For netlink access (preferred):** CAP_NET_ADMIN capability or root
- **For sudo fallback:** Passwordless sudo access to ipset commands (see Permissions section)

## Installation

### Using xcaddy

```bash
xcaddy build --with github.com/deovero/caddy-ipset
```

### Manual Build

1. Clone this repository
2. Build with Go:
```bash
go build
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

This automatically extracts the real client IP from headers like `X-Forwarded-For`, `X-Real-IP`, or `Cf-Connecting-IP` when the request comes from a trusted proxy.

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

## Permissions

The module automatically selects the best access method based on available permissions:

### Option 1: Grant CAP_NET_ADMIN capability (recommended for best performance)

This enables direct netlink access for maximum performance:

```bash
sudo setcap cap_net_admin+ep /usr/bin/caddy
```

**Advantages:**
- Fastest performance (direct kernel communication)
- No process spawning overhead
- No sudo configuration needed

### Option 2: Configure passwordless sudo (recommended for non-privileged users)

If Caddy runs as a non-privileged user without CAP_NET_ADMIN, the module automatically falls back to `sudo ipset`. Configure passwordless sudo by adding to `/etc/sudoers.d/caddy`:

```
caddy ALL=(ALL) NOPASSWD: /usr/sbin/ipset
```

**Advantages:**
- Works with non-privileged Caddy processes
- No capability management needed
- Automatic fallback (no configuration required)

**Note:** Make sure to use `visudo -f /etc/sudoers.d/caddy` to edit the file safely.

### Option 3: Run Caddy as root (not recommended for production)

```bash
sudo caddy run
```

**Only use this for testing!** Running web servers as root is a security risk.

## Logging

The module provides detailed logging:

- **Info**:
  - When the module is provisioned (includes which access method is being used: "netlink" or "sudo")
  - When an IP matches the ipset
- **Warn**: When netlink access is denied and falling back to sudo
- **Debug**: When an IP is not in the ipset
- **Error**: When there are issues parsing IPs or accessing ipset

Example log output:
```
INFO ipset matcher provisioned using native netlink {"ipset": "blocklist", "method": "netlink"}
```
or
```
WARN netlink access denied, falling back to sudo ipset {"ipset": "blocklist"}
INFO ipset matcher provisioned using sudo fallback {"ipset": "blocklist", "method": "sudo"}
```

## Testing

### Running Tests

```bash
go test -v
```

### Testing the Module

To test if the module is working correctly:

1. Create a test ipset:
```bash
sudo ipset create test-ipset hash:ip
sudo ipset add test-ipset 127.0.0.1
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
	@matched {
		ipset test-ipset
	}
	handle @matched {
		respond "IP is in the set!" 200
	}
	respond "IP is not in the set" 200
}
```

3. Execute Caddy:
```bash
./caddy run
```

4. Test with curl:
```bash
curl -4 http://localhost:20080
# Should return "IP is in the set!" if your IP is 127.0.0.1
```

## Troubleshooting

### "ipset does not exist or cannot be accessed"

**Cause**: The ipset list doesn't exist or Caddy doesn't have permission to access it.

**Solution**:
1. Verify the ipset exists: `sudo ipset list <name>`
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

### Permission denied errors

**Cause**: Caddy doesn't have permission to access netlink or run sudo ipset.

**Solution**:
1. Check the logs to see which method is being used ("netlink" or "sudo")
2. For netlink: Grant CAP_NET_ADMIN capability (see Permissions section)
3. For sudo fallback: Configure passwordless sudo (see Permissions section)
4. Verify the ipset kernel module is loaded: `lsmod | grep ip_set`

### Sudo password prompts or "sudo: no tty present"

**Cause**: The sudo configuration requires a password, but Caddy can't provide one interactively.

**Solution**: Configure passwordless sudo for the caddy user (see Permissions section, Option 2). Make sure the sudoers file includes `NOPASSWD` for the ipset command.

### Module using sudo fallback but you want netlink

**Cause**: Caddy doesn't have CAP_NET_ADMIN capability.

**Solution**: Grant the capability to the Caddy binary:
```bash
sudo setcap cap_net_admin+ep /usr/bin/caddy
```
Then restart Caddy. Check the logs - you should see "method: netlink" instead of "method: sudo".

## License

Apache License 2.0 - see LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Authors

- [DeoVero](https://deovero.com) - [Jeroen Vermeulen](https://www.linkedin.com/in/jeroenvermeuleneu/)
- [Augment Code](https://www.augmentcode.com/)