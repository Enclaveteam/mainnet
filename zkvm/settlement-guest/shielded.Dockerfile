# Marlin Oyster CVM image for the Zstable BLIND SEQUENCER — the enclave service that decrypts the
# sealed order, executes it, and generates the SP1 proof INSIDE, so the operator never sees the order.
#
# Build context MUST be packages/zkvm (so the settlement-guest path dep ../../settlement-executor resolves).
# Building the SP1 guest ELF needs the Succinct toolchain.
#
#   docker build --platform linux/amd64 -f settlement-guest/shielded.Dockerfile -t ghcr.io/<you>/zstable-shielded-sequencer .
#
# NOTE: this build installs the SP1 toolchain and compiles the guest program; it is heavy (~10 min+).
FROM rust:1-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git build-essential pkg-config libssl-dev unzip \
    && rm -rf /var/lib/apt/lists/*
# Official protoc — bundles the well-known types (google/protobuf/empty.proto, ...). The Debian
# package with --no-install-recommends doesn't provide them ("google.protobuf.Empty is not defined").
ARG PROTOC_VERSION=27.3
RUN curl -fsSL -o /tmp/protoc.zip "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" \
    && unzip -o /tmp/protoc.zip -d /usr/local 'bin/protoc' 'include/*' \
    && rm /tmp/protoc.zip
ENV PROTOC=/usr/local/bin/protoc
# Succinct SP1 toolchain (needed by settlement-guest build.rs to build the guest ELF).
RUN curl -L https://sp1up.succinct.xyz | bash && /root/.sp1/bin/sp1up
ENV PATH="/root/.sp1/bin:${PATH}"
WORKDIR /build
COPY settlement-executor ./settlement-executor
COPY settlement-guest ./settlement-guest
RUN cd settlement-guest && cargo build --release --bin shielded-sequencer

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/settlement-guest/target/release/shielded-sequencer /usr/local/bin/shielded-sequencer
ENV PORT=4000
EXPOSE 4000
ENTRYPOINT ["/usr/local/bin/shielded-sequencer"]
