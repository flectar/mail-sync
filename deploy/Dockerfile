# syntax=docker/dockerfile:1
#
# Build: docker buildx build -f deploy/Dockerfile --platform linux/amd64,linux/arm64 .
# The build stage runs natively and cross-compiles for arm64, which is far
# faster than emulating the target architecture.

FROM --platform=$BUILDPLATFORM rust:1.99-slim-trixie AS build
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu; \
             apt-get update; \
             apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross; \
             rm -rf /var/lib/apt/lists/* ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    echo "$target" > /rust-target
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    target="$(cat /rust-target)"; \
    cargo build --release --locked -p flectar-mail-sync-server --target "$target"; \
    cp "target/$target/release/flectar-mail-sync-server" /flectar-mail-sync-server; \
    mkdir -p /data

# glibc runtime: musl's default allocator is slow for multithreaded servers.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /flectar-mail-sync-server /usr/local/bin/flectar-mail-sync-server
COPY --from=build --chown=65532:65532 /data /data
COPY LICENSE.md LICENSES /usr/share/doc/flectar-mail-sync/
ENV FLECTAR_MAIL_SYNC_DATABASE=/data/sync.db \
    FLECTAR_MAIL_SYNC_LISTEN=0.0.0.0:8080
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --start-interval=2s \
    CMD ["/usr/local/bin/flectar-mail-sync-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/flectar-mail-sync-server"]
CMD ["serve"]
