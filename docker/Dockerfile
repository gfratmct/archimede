# Multi-stage build for the Archimede daemon (Linux target — full /proc + sockets).
FROM rust:1.85-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY configs ./configs

RUN cargo build --release -p archimede

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /etc/archimede

COPY --from=builder /src/target/release/archimede /usr/local/bin/archimede
COPY docker/archimede.yaml /etc/archimede/archimede.yaml

WORKDIR /data
EXPOSE 7432
VOLUME ["/data"]

ENTRYPOINT ["archimede"]
CMD ["--config", "/etc/archimede/archimede.yaml", "daemon"]
