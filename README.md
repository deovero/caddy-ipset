# Caddy IPSet Matcher

A Caddy HTTP matcher module that matches requests based on client IP addresses against Linux ipset lists.

## Features

- **Native kernel communication** - Uses netlink to communicate directly with the Linux kernel (no shell commands)
- Match HTTP requests against existing Linux ipset lists
- Uses Caddy's built-in client IP detection (respects `trusted_proxies` configuration)
- Automatic support for X-Forwarded-For, X-Real-IP, Cf-Connecting-IP headers via `trusted_proxies`
- Automatic ipset validation on startup
- Comprehensive logging for debugging and monitoring
- Simple Caddyfile and JSON configuration
- High performance with minimal overhead
- Comprehensive unit tests

## How It Works

This module integrates with Caddy's request matcher system to check if a client's IP address is present in a specified Linux ipset. It uses the `vishvananda/netlink` library to communicate directly with the Linux kernel via netlink, providing native, high-performance ipset lookups without spawning external processes.

## Requirements

- Linux system with ipset kernel module loaded
- Caddy v2
- Appropriate permissions to access netlink (typically requires root or CAP_NET_ADMIN capability)

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

Caddy needs permission to run `ipset` commands. Options:

### Option 1: Run Caddy as root (not recommended)
```bash
sudo caddy run
```

### Option 2: Grant CAP_NET_ADMIN capability (recommended)
```bash
sudo setcap cap_net_admin+ep /usr/bin/caddy
```

### Option 3: Use sudo with NOPASSWD for ipset
Add to `/etc/sudoers.d/caddy`:
```
caddy ALL=(ALL) NOPASSWD: /usr/sbin/ipset
```

Then modify the plugin to use `sudo ipset` (requires code modification).

## Logging

The module provides detailed logging:

- **Info**: When an IP matches the ipset
- **Debug**: When an IP is not in the ipset
- **Error**: When there are issues parsing IPs or running ipset commands

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
```caddyfile
{
    admin off
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

3. Test with curl:
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

**Cause**: Caddy doesn't have permission to access netlink.

**Solution**: See the Permissions section above for different options to grant access. Also verify the ipset kernel module is loaded with `lsmod | grep ip_set`.

## License

Apache License 2.0 - see LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Authors

- [DeoVero](https://deovero.com) - [Jeroen Vermeulen](https://www.linkedin.com/in/jeroenvermeuleneu/)
- [Augment Code](https://www.augmentcode.com/)