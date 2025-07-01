# Build stage
FROM rust:1.86-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this will be cached if Cargo.toml doesn't change)
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r rustress \
    && useradd -r -g rustress rustress

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rustress .

# Create directory for SQLite database and set permissions
RUN mkdir -p /app/data && chown -R rustress:rustress /app

# Expose port
EXPOSE 8080

# Set environment variables (only DATABASE_URL and RUST_LOG have defaults)
ENV DATABASE_URL=sqlite:rustress.db
ENV RUST_LOG=info
ENV BIND_ADDRESS=0.0.0.0


# Run the application
CMD ["./rustress"]
