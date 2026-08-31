# Build stage
FROM rust:1.98 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin engine  

# Runtime stage
FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/engine .

COPY ./aho_patterns.txt .
EXPOSE 4000
CMD ["./engine"]
