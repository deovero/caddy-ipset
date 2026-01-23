#!/bin/bash
# Script to set up test ipsets for testing
# Used by both Docker and CI environments

set -e

# Load ipset kernel module if not already loaded (may fail in some environments, that's ok)
modprobe ip_tables 2>/dev/null || true
modprobe ip_set 2>/dev/null || true
modprobe ip_set_hash_ip 2>/dev/null || true
modprobe ip_set_hash_net 2>/dev/null || true

# Create IPv4 test ipsets
ipset create test-ipset hash:ip 2>/dev/null || ipset flush test-ipset
ipset create blocklist hash:ip 2>/dev/null || ipset flush blocklist
ipset create empty hash:ip 2>/dev/null || ipset flush empty

# Create IPv6 test ipsets
ipset create test-ipset-v6 hash:ip family inet6 2>/dev/null || ipset flush test-ipset-v6
ipset create blocklist-v6 hash:ip family inet6 2>/dev/null || ipset flush blocklist-v6
ipset create empty-v6 hash:ip family inet6 2>/dev/null || ipset flush empty-v6

# Add some test IPv4 addresses
ipset add test-ipset 127.0.0.1 2>/dev/null || true
ipset add test-ipset 192.168.1.100 2>/dev/null || true
ipset add blocklist 10.0.0.1 2>/dev/null || true

# Add some test IPv6 addresses
ipset add test-ipset-v6 ::1 2>/dev/null || true
ipset add test-ipset-v6 2001:db8::1 2>/dev/null || true
ipset add test-ipset-v6 fe80::1 2>/dev/null || true
ipset add blocklist-v6 2001:db8::bad 2>/dev/null || true

echo "Test ipsets created successfully"
ipset list -n

