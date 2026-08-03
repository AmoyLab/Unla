FROM golang:1.25.0 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=linux go build -o mcp-gateway ./cmd/mcp-gateway

FROM ubuntu:22.04
WORKDIR /app

# Set default timezone
ENV TZ=UTC

RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata

COPY --from=builder /app/mcp-gateway .
COPY --from=builder /app/configs/mcp-gateway.yaml /etc/unla/
COPY --from=builder /app/assets /app/assets

# Create data directory
RUN mkdir -p /app/data

EXPOSE 5235
CMD ["./mcp-gateway"]
