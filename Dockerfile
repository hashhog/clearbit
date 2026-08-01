# Stage 1: Build
FROM debian:bookworm-slim AS builder
# NOTE: no libsecp256k1-dev — Debian's package is too old (no
# secp256k1_ellswift.h, which src/secp.zig's @cImport requires for BIP-324)
# and its headers in /usr/include would shadow the source-built ones.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates xz-utils librocksdb-dev libsnappy-dev curl \
    git build-essential autoconf automake libtool pkg-config && \
    rm -rf /var/lib/apt/lists/*
# libsecp256k1 v0.7.1 from source (installs into /usr/local).
RUN git clone --depth 1 --branch v0.7.1 https://github.com/bitcoin-core/secp256k1 /tmp/secp256k1 && \
    cd /tmp/secp256k1 && \
    ./autogen.sh && \
    ./configure --enable-module-ecdh --enable-module-recovery --enable-module-extrakeys --enable-module-schnorrsig --enable-module-ellswift && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    rm -rf /tmp/secp256k1
RUN curl -fsSL https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \
    | tar -xJ -C /usr/local && \
    ln -s /usr/local/zig-linux-x86_64-0.13.0/zig /usr/local/bin/zig
WORKDIR /build
COPY . .
RUN zig build -Doptimize=ReleaseFast -Drocksdb=true --search-prefix /usr/local

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates librocksdb-dev && \
    rm -rf /var/lib/apt/lists/*
# Source-built libsecp256k1 (soname 6) from the builder stage.
COPY --from=builder /usr/local/lib/libsecp256k1.so* /usr/local/lib/
RUN ldconfig
COPY --from=builder /build/zig-out/bin/clearbit /usr/local/bin/clearbit
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["clearbit"]
CMD ["--datadir=/data"]
