# syntax=docker/dockerfile:1
#
# The broker as a container image. The only input is CONFIG_STORE_PATH
# (see docs/configuration.md): mount the Turtle config at the default path
# below, or point the variable at another file, directory or http(s) URL.
# The config must set broker:httpApiAddr to a non-loopback address, such as
# "0.0.0.0:8080", for the port to be reachable from outside the container.
#
# Build from a checkout with the vendored submodules present:
#   git submodule update --init vendor/contreforts-*
#   docker build -t ds-catalog-broker-rs .

FROM rust:1.97-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release -p ds-catalog-broker-rs --bin ds-catalog-broker-rs \
    && install -D target/release/ds-catalog-broker-rs /out/ds-catalog-broker-rs

# glibc and libgcc only: TLS is rustls with built-in roots, and Oxigraph is
# pure Rust here (no RocksDB). Runs as the image's unprivileged user.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/ds-catalog-broker-rs /usr/local/bin/ds-catalog-broker-rs
ENV CONFIG_STORE_PATH=/etc/ds-catalog-broker/config.ttl
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ds-catalog-broker-rs"]
