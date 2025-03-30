FROM golang:1.21 AS builder
WORKDIR /app
COPY . .

RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/certs
RUN go build -o proxy .

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/proxy .
COPY --from=builder /app/certs /app/certs

EXPOSE 8080 8000
CMD ["./proxy"]