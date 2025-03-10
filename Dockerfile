###############################################################################
# Build Stage - Compile the NanoVM with all features
###############################################################################
FROM rust:1.70.0-slim-bullseye AS builder

# Set working directory
WORKDIR /usr/src/nanovm

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    musl-tools \
    clang \
    lld \
    && rm -rf /var/lib/apt/lists/*

# Create empty project for caching dependencies
RUN cargo new --bin .
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo ./.cargo

# Build dependencies (cache layer)
RUN cargo build --release --features enterprise

# Copy actual source code
COPY src ./src/
COPY benches ./benches/
COPY tests ./tests/

# Clean and rebuild with real source
RUN cargo clean -p nanovm && \
    cargo build --release --features enterprise --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/nanovm

###############################################################################
# Runtime Stage - Create minimal container with just the binary
###############################################################################
FROM alpine:3.17 as runtime

# Create non-root user for security
RUN addgroup -g 1000 nanovm && \
    adduser -u 1000 -G nanovm -s /bin/sh -D nanovm

# Create directory structure
RUN mkdir -p /etc/nanovm /var/lib/nanovm /var/log/nanovm /var/run/nanovm && \
    chown -R nanovm:nanovm /etc/nanovm /var/lib/nanovm /var/log/nanovm /var/run/nanovm

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    libseccomp

# Copy binary from builder
COPY --from=builder /usr/src/nanovm/target/x86_64-unknown-linux-musl/release/nanovm /usr/local/bin/nanovm

# Copy default configuration
COPY nanovm_config.yaml /etc/nanovm/nanovm_config.yaml

# Set proper permissions
RUN chmod 550 /usr/local/bin/nanovm && \
    chmod 640 /etc/nanovm/nanovm_config.yaml && \
    chown nanovm:nanovm /etc/nanovm/nanovm_config.yaml

# Set environment variables
ENV RUST_LOG=info \
    TZ=UTC \
    NANOVM_CONFIG=/etc/nanovm/nanovm_config.yaml

# Expose ports
EXPOSE 8080 443

# Switch to non-root user
USER nanovm
WORKDIR /var/lib/nanovm

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/nanovm"]
CMD ["--config", "/etc/nanovm/nanovm_config.yaml"]

# Add health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

# Add metadata
LABEL org.opencontainers.image.title="NanoVM" \
      org.opencontainers.image.description="Enterprise-grade rootless virtualization system with mTLS 1.2+ support" \
      org.opencontainers.image.vendor="TheMapleseed" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.source="https://github.com/TheMapleseed/NANOVM" \
      com.nanovm.version="0.1.0" \
      com.nanovm.security.mtls="enabled" \
      com.nanovm.security.min-tls="1.2" 