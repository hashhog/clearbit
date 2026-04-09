# Stage 1: Build
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates xz-utils librocksdb-dev libsecp256k1-dev curl && \
    rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \
    | tar -xJ -C /usr/local && \
    ln -s /usr/local/zig-linux-x86_64-0.13.0/zig /usr/local/bin/zig
WORKDIR /build
COPY . .
RUN zig build -Doptimize=ReleaseFast -Drocksdb=true

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates librocksdb-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/zig-out/bin/clearbit /usr/local/bin/clearbit
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["clearbit"]
CMD ["--datadir=/data"]
