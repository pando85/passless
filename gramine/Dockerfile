# Gramine Shielded Container (GSC) for Passless
# This Dockerfile creates a containerized SGX-enabled Passless

# Stage 1: Build Passless
FROM rust:1.75 AS builder

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY passless-core ./passless-core
COPY passless-config-doc ./passless-config-doc
COPY cmd/passless ./cmd/passless

# Build release binary
RUN cargo build --release

# Stage 2: Create minimal runtime image
FROM ubuntu:22.04

# Install Gramine and dependencies
RUN apt-get update && apt-get install -y \
    gramine \
    libsgx-enclave-common \
    libsgx-urts \
    libsgx-launch \
    && rm -rf /var/lib/apt/lists/*

# Create passless user and directories
RUN useradd -r -s /bin/false passless && \
    mkdir -p /var/lib/passless && \
    chown passless:passless /var/lib/passless

# Copy binary from builder
COPY --from=builder /build/target/release/passless /usr/bin/passless

# Copy Gramine manifest
COPY gramine/passless.manifest.template /etc/passless/passless.manifest.template

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Generate manifest if needed\n\
if [ ! -f /etc/passless/passless.manifest ]; then\n\
    gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu \\\n\
        /etc/passless/passless.manifest.template \\\n\
        /etc/passless/passless.manifest\n\
fi\n\
\n\
# Sign manifest if needed\n\
if [ ! -f /etc/passless/passless.manifest.sgx ]; then\n\
    gramine-sgx-sign --key /etc/passless/enclave-key.pem \\\n\
        --manifest /etc/passless/passless.manifest \\\n\
        --output /etc/passless/passless.manifest.sgx\n\
fi\n\
\n\
# Run passless in SGX enclave\n\
exec gramine-sgx /etc/passless/passless\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

# Expose UHID device
VOLUME ["/dev/uhid", "/var/lib/passless"]

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["--backend-type", "local", "--local-path", "/var/lib/passless"]