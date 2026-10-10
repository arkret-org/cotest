FROM rust:bookworm AS build

WORKDIR /workspace
RUN apt-get update && apt-get install -y --no-install-recommends jq \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTFLAGS="-C link-arg=-lssl -C link-arg=-lcrypto"
COPY arkret-rust-sdk ./arkret-rust-sdk
COPY arkret-spec ./arkret-spec
COPY garth ./garth
COPY chime ./chime
COPY inkson ./inkson
COPY floria ./floria
COPY coauth ./coauth
COPY cotest ./cotest
COPY soland ./soland

WORKDIR /workspace/soland
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/soland/target \
    cargo build --release --locked --features conformance-harness \
    && target_dir="$(cargo metadata --locked --format-version 1 --no-deps | jq -er .target_directory)" \
    && cp "$target_dir/release/soland" /tmp/soland

FROM debian:bookworm-slim

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /tmp/soland /usr/local/bin/soland

ENV SOLAND_BIND=0.0.0.0:8008
ENV SOLAND_DEVELOPMENT_MODE=1
ENV SOLAND_BLOB_ROOT=/tmp/soland-blobs

EXPOSE 8008

ENTRYPOINT ["soland"]
