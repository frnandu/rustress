FROM rust:1.86-slim as builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rustress .
COPY static ./static
EXPOSE 8080
ENV DATABASE_URL=sqlite:rustress.db
ENV RUST_LOG=info
ENV BIND_ADDRESS=0.0.0.0
CMD ["./rustress"]
