FROM rust:1.92-bookworm AS build

WORKDIR /workspace
ENV RUSTFLAGS="-C link-arg=-lssl -C link-arg=-lcrypto"
COPY contrix-rust-sdk ./contrix-rust-sdk
COPY soland ./soland

WORKDIR /workspace/soland
RUN cargo build --release

FROM rust:1.92-bookworm

WORKDIR /app
COPY --from=build /workspace/soland/target/release/soland /usr/local/bin/soland

ENV SERVERX_BIND=0.0.0.0:8008
ENV SERVERX_DEVELOPMENT_MODE=1
ENV SERVERX_BLOB_ROOT=/tmp/soland-blobs

EXPOSE 8008

ENTRYPOINT ["soland"]
