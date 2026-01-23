# Dockerfile for testing caddy-ipset on macOS
FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    ipset \
    iptables \
    sudo \
    curl \
    git \
    ca-certificates \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.25
# Detect architecture and download appropriate Go binary
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        GO_ARCH="amd64"; \
    elif [ "$ARCH" = "arm64" ]; then \
        GO_ARCH="arm64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl -fsSL https://go.dev/dl/go1.25.0.linux-${GO_ARCH}.tar.gz -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

# Set up Go environment
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"
ENV CGO_ENABLED=1

# Create a non-root user for testing
RUN useradd -m -s /bin/bash testuser \
    && echo "testuser ALL=(ALL) NOPASSWD: /usr/sbin/ipset" >> /etc/sudoers

# Set working directory
WORKDIR /workspace

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Load ipset kernel module and create test ipsets
# Note: This requires --privileged flag when running the container
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Load ipset module if not already loaded\n\
modprobe ip_tables 2>/dev/null || true\n\
modprobe ip_set 2>/dev/null || true\n\
modprobe ip_set_hash_ip 2>/dev/null || true\n\
modprobe ip_set_hash_net 2>/dev/null || true\n\
\n\
# Create IPv4 test ipsets\n\
ipset create test-ipset hash:ip 2>/dev/null || ipset flush test-ipset\n\
ipset create blocklist hash:ip 2>/dev/null || ipset flush blocklist\n\
ipset create empty hash:ip 2>/dev/null || ipset flush empty\n\
\n\
# Create IPv6 test ipsets\n\
ipset create test-ipset-v6 hash:ip family inet6 2>/dev/null || ipset flush test-ipset-v6\n\
ipset create blocklist-v6 hash:ip family inet6 2>/dev/null || ipset flush blocklist-v6\n\
ipset create empty-v6 hash:ip family inet6 2>/dev/null || ipset flush empty-v6\n\
\n\
# Add some test IPv4 addresses\n\
ipset add test-ipset 127.0.0.1 2>/dev/null || true\n\
ipset add test-ipset 192.168.1.100 2>/dev/null || true\n\
ipset add blocklist 10.0.0.1 2>/dev/null || true\n\
\n\
# Add some test IPv6 addresses\n\
ipset add test-ipset-v6 ::1 2>/dev/null || true\n\
ipset add test-ipset-v6 2001:db8::1 2>/dev/null || true\n\
ipset add test-ipset-v6 fe80::1 2>/dev/null || true\n\
ipset add blocklist-v6 2001:db8::bad 2>/dev/null || true\n\
\n\
echo "Test ipsets created successfully"\n\
ipset list -n\n\
' > /usr/local/bin/setup-ipsets.sh \
    && chmod +x /usr/local/bin/setup-ipsets.sh

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Setup ipsets\n\
/usr/local/bin/setup-ipsets.sh\n\
\n\
# Execute the command passed to docker run\n\
exec "$@"\n\
' > /entrypoint.sh \
    && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]

