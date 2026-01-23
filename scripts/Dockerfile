# Dockerfile for testing caddy-ipset on macOS
FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    ipset \
    iptables \
    libcap2-bin \
    curl \
    git \
    ca-certificates \
    gcc \
    libc6-dev \
    sudo \
    debian-keyring \
    debian-archive-keyring \
    apt-transport-https \
    gpg \
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
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CGO_ENABLED=1

# Install xcaddy
RUN curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-xcaddy-archive-keyring.gpg && \
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-xcaddy.list && \
    apt-get update && \
    apt-get install -y xcaddy && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user for testing
RUN useradd -m -s /bin/bash testuser

# Set working directory
WORKDIR /workspace

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Install the shared setup script
RUN cp scripts/setup-test-ipsets.sh /usr/local/bin/setup-test-ipsets.sh \
    && chmod +x /usr/local/bin/setup-test-ipsets.sh

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Setup ipsets\n\
/usr/local/bin/setup-test-ipsets.sh\n\
\n\
# Execute the command passed to docker run\n\
exec "$@"\n\
' > /entrypoint.sh \
    && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
