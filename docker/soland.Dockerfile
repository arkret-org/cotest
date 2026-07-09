FROM rust:1.96-bookworm AS build

WORKDIR /workspace
ENV RUSTFLAGS="-C link-arg=-lssl -C link-arg=-lcrypto"
COPY arkret-rust-sdk ./arkret-rust-sdk
COPY soland ./soland

WORKDIR /workspace/soland
RUN cargo build --release --locked

FROM debian:bookworm-slim

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /workspace/soland/target/release/soland /usr/local/bin/soland

ENV SOLAND_BIND=0.0.0.0:8008
ENV SOLAND_DEVELOPMENT_MODE=1
ENV SOLAND_BLOB_ROOT=/tmp/soland-blobs

EXPOSE 8008

ENTRYPOINT ["soland"]
