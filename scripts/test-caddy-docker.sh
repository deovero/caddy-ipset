#!/bin/bash
# End-to-end test inside the Docker container: build Caddy with this module using xcaddy,
# grant it capabilities with =+p (not =+ep), run it as a non-root user on a privileged
# port and check the ipset matcher.
#
# Usage: test-caddy-docker.sh [caddy-version]   (default: v2.11.8, needs >= v2.11.8 for =+p)

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

CADDY_VERSION="${1:-v2.11.8}"
WORKDIR=/tmp/caddy-e2e
CADDY_BIN="$WORKDIR/caddy"

if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && ! grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo -e "${RED}Error: This script must be run inside a Docker container${NC}"
    exit 1
fi

echo -e "${YELLOW}Setting up test ipsets...${NC}"
/workspace/scripts/setup-test-ipsets.sh >/dev/null

mkdir -p "$WORKDIR"
echo -e "${YELLOW}Building Caddy ${CADDY_VERSION} with this module...${NC}"
GOTOOLCHAIN=auto xcaddy build "$CADDY_VERSION" --with github.com/deovero/caddy-ipset=/workspace --output "$CADDY_BIN"
"$CADDY_BIN" version

echo -e "${YELLOW}Granting cap_net_bind_service,cap_net_admin=+p...${NC}"
setcap 'cap_net_bind_service,cap_net_admin=+p' "$CADDY_BIN"
getcap "$CADDY_BIN"

cat > "$WORKDIR/Caddyfile" <<'EOF'
{
	admin off
	auto_https off
	servers {
		trusted_proxies static 127.0.0.1/32
		client_ip_headers X-Forwarded-For
	}
	log {
		level DEBUG
	}
}
:80 {
	@v4 ipset test-ipset-v4
	handle @v4 {
		respond "in test-ipset-v4" 200
	}
	@blocklist ipset blocklist-v4
	handle @blocklist {
		respond "in blocklist-v4" 200
	}
	respond "not in any ipset" 403
}
EOF
mkdir -p "$WORKDIR/data" "$WORKDIR/config"
chown testuser "$WORKDIR/data" "$WORKDIR/config"
chmod -R a+rX "$WORKDIR"

echo -e "${YELLOW}Starting Caddy as testuser on :80...${NC}"
su testuser -s /bin/bash -c "XDG_DATA_HOME=/tmp/caddy-e2e/data XDG_CONFIG_HOME=/tmp/caddy-e2e/config $CADDY_BIN run --config $WORKDIR/Caddyfile" \
    > "$WORKDIR/caddy.log" 2>&1 &
for _ in $(seq 1 50); do
    curl -s -o /dev/null http://127.0.0.1:80/ && break
    sleep 0.2
done

# The Caddy process itself (not the root-owned su wrapper)
CADDY_PID=$(pgrep -u testuser -x caddy | head -n 1 || true)
cleanup() { [ -n "$CADDY_PID" ] && kill "$CADDY_PID" 2>/dev/null || true; }
trap cleanup EXIT

FAILED=0
check() {
    local desc="$1" expected="$2"; shift 2
    local got
    got=$(curl -s -o /dev/null -w '%{http_code}' "$@" || true)
    if [ "$got" = "$expected" ]; then
        echo -e "${GREEN}✓ ${desc}: HTTP ${got}${NC}"
    else
        echo -e "${RED}✗ ${desc}: HTTP ${got}, expected ${expected}${NC}"
        FAILED=1
    fi
}

if [ -z "$CADDY_PID" ]; then
    echo -e "${RED}✗ Caddy is not running${NC}"
    FAILED=1
else
    echo -e "${YELLOW}Process capabilities of Caddy (pid ${CADDY_PID}):${NC}"
    grep -E '^Cap(Prm|Eff)' "/proc/$CADDY_PID/status"

    check "127.0.0.1 is in test-ipset-v4" 200 http://127.0.0.1:80/
    check "10.0.0.1 is in blocklist-v4" 200 -H 'X-Forwarded-For: 10.0.0.1' http://127.0.0.1:80/
    check "8.8.8.8 is not in any ipset" 403 -H 'X-Forwarded-For: 8.8.8.8' http://127.0.0.1:80/
    # Some concurrent load, so lookups run on many threads at once
    CURL_PIDS=()
    for _ in $(seq 1 200); do
        curl -s -o /dev/null -H 'X-Forwarded-For: 10.0.0.1' http://127.0.0.1:80/ &
        CURL_PIDS+=($!)
    done
    # Only wait for the curls, a bare `wait` would also wait for Caddy
    wait "${CURL_PIDS[@]}"
    check "after concurrent load" 200 -H 'X-Forwarded-For: 10.0.0.1' http://127.0.0.1:80/

    # Every thread must have CAP_NET_ADMIN (bit 12) and CAP_NET_BIND_SERVICE (bit 10) dropped from its effective set
    LEAKED=0
    for status in /proc/"$CADDY_PID"/task/*/status; do
        eff=$(awk '/^CapEff:/ {print $2}' "$status" 2>/dev/null || true)
        [ -z "$eff" ] && continue
        if (( (16#$eff & ((1 << 12) | (1 << 10))) != 0 )); then
            echo -e "${RED}✗ thread $(basename "$(dirname "$status")") has CapEff=$eff${NC}"
            LEAKED=1
        fi
    done
    if [ $LEAKED -eq 0 ]; then
        echo -e "${GREEN}✓ no thread has CAP_NET_ADMIN or CAP_NET_BIND_SERVICE effective${NC}"
    else
        FAILED=1
    fi
fi

echo ""
echo -e "${YELLOW}Caddy log (ipset lines):${NC}"
grep -iE 'ipset|CAP_NET|error' "$WORKDIR/caddy.log" | head -n 20 || true

echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}End-to-end test passed${NC}"
else
    echo -e "${RED}End-to-end test failed, full log: ${WORKDIR}/caddy.log${NC}"
    tail -n 30 "$WORKDIR/caddy.log"
    exit 1
fi
