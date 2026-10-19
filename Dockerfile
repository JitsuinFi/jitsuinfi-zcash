# HNK-09.T2: `jitsuin verify` for judges, with zcash-devtool for the live board scan.
#   docker build -t jitsuin .
#   docker run --rm jitsuin verify --board examples/verify/board-sample.json \
#     --proof examples/verify/proof-sample.txt --bundle examples/verify/bundle-sample.txt
# No spending key and no ZEC: the board is read with its viewing key only.

FROM rust:1.99.1-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config git ca-certificates \
      libsqlite3-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
# jitsuin-wallet parses devtool's text output; this is the commit it is tested against (ES-HNK-03).
ARG ZCASH_DEVTOOL_REV=b532d4cd760d30213c961fe0638ee6b6e1bf8e30
RUN cargo install --locked --git https://github.com/zcash/zcash-devtool --rev "${ZCASH_DEVTOOL_REV}" zcash-devtool
WORKDIR /src
COPY . .
# The image already has 1.99.1; skip the components rust-toolchain.toml asks for (fmt, clippy).
ENV RUSTUP_TOOLCHAIN=1.99.1
RUN cargo install --locked --path crates/jitsuin-cli --root /out

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 libssl3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 jitsuin \
 && mkdir -p /work/wallet-board-testnet /work/wallet-board-mainnet \
 && chown -R jitsuin:jitsuin /work
COPY --from=build /usr/local/cargo/bin/zcash-devtool /usr/local/bin/zcash-devtool
COPY --from=build /out/bin/jitsuin /usr/local/bin/jitsuin
COPY --chown=jitsuin:jitsuin examples /work/examples
WORKDIR /work
USER jitsuin
ENTRYPOINT ["jitsuin"]
CMD ["--help"]
