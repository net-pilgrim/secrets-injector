# syntax=docker/dockerfile:1
FROM debian:bookworm-slim AS builder

ARG ZIG_VERSION=0.13.0
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) ZIG_ARCH="x86_64" ;; \
      arm64) ZIG_ARCH="aarch64" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz; \
    tar -xf /tmp/zig.tar.xz -C /opt; \
    ln -s "/opt/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}/zig" /usr/local/bin/zig; \
    rm /tmp/zig.tar.xz; \
    zig version

WORKDIR /build
COPY build.zig ./
COPY src/ ./src/
COPY test/ ./test/

# Build optimized ReleaseSmall shared libraries (glibc and musl flavours) and verify unit tests
RUN zig build -Doptimize=ReleaseSmall
RUN zig build test-unit

# Stage 2: Minimal runtime image for sidecar / init container usage
FROM alpine:3.20

LABEL org.opencontainers.image.title="secrets-injector" \
      org.opencontainers.image.description="Transparent LD_PRELOAD secrets injector for glibc and musl containers" \
      org.opencontainers.image.source="https://github.com/net-pilgrim/secrets-injector"

WORKDIR /secrets-injector

# Install libraries into standard search paths
COPY --from=builder /build/zig-out/lib/libsecrets_injector.so /usr/local/lib/libsecrets_injector.so
COPY --from=builder /build/zig-out/lib/libsecrets_injector_glibc.so /usr/local/lib/libsecrets_injector_glibc.so
COPY --from=builder /build/zig-out/lib/libsecrets_injector_musl.so /usr/local/lib/libsecrets_injector_musl.so

RUN ln -s /usr/local/lib/libsecrets_injector.so /libsecrets_injector.so && \
    ln -s /usr/local/lib/libsecrets_injector_glibc.so /libsecrets_injector-glibc.so && \
    ln -s /usr/local/lib/libsecrets_injector_musl.so /libsecrets_injector-musl.so

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENV TARGET_DIR=/shared
VOLUME ["/shared"]

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["copy"]
