# Caddy IPSet Matcher

A Caddy HTTP matcher module that matches requests based on client IP addresses against Linux ipset lists.

## Features

- Match HTTP requests against existing Linux ipset lists
- Support for Cloudflare's `Cf-Connecting-Ip` header
- Automatic ipset validation on startup
- Comprehensive logging for debugging and monitoring
- Simple Caddyfile and JSON configuration

## Requirements

- Linux system with `ipset` utility installed
- Caddy v2
- Appropriate permissions to run `ipset` commands (typically requires root or CAP_NET_ADMIN capability)

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

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Author

DeoVero - Jeroen Vermeulen

