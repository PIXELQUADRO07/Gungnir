# Build stage
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    libreadline-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the project
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libsqlite3-0 \
    libreadline8 \
    nmap \
    exploitdb \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/Gungnir /usr/local/bin/Gungnir

# Create data directory
RUN mkdir -p /root/.gungnir

# Default command
ENTRYPOINT ["Gungnir"]
