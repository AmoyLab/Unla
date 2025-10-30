FROM golang:1.24.1 AS apiserver-builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the Go service
RUN GOOS=linux go build -o apiserver ./cmd/apiserver

FROM node:20.18.0 AS web-builder

WORKDIR /app/web

COPY web/ .

RUN npm install -g pnpm@9.15.0
RUN pnpm install --frozen-lockfile
RUN pnpm run build

FROM nginx:1.29.1-bookworm

WORKDIR /app

# Set default timezone
ENV TZ=UTC

RUN apt-get update && apt-get install -y \
    tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata

# Copy apiserver binary and config
COPY --from=apiserver-builder /app/apiserver /app/
COPY --from=apiserver-builder /app/configs/apiserver.yaml /etc/unla/
COPY configs/i18n /etc/unla/i18n

# Create data directory for apiserver with proper permissions
RUN mkdir -p /app/data && \
    chmod -R 777 /app/data && \
    mkdir -p /tmp/mcp-gateway && \
    chmod -R 777 /tmp/mcp-gateway

# Copy web files to nginx html directory
COPY --from=web-builder /app/web/dist /usr/share/nginx/html

# Copy nginx configuration
COPY deploy/docker/multi/web/nginx.conf /etc/nginx/nginx.conf

# Expose ports
EXPOSE 80 5234

# Create startup script
RUN echo '#!/bin/bash\n\
nginx &\n\
exec /app/apiserver\n' > /app/start.sh && \
chmod +x /app/start.sh

CMD ["/app/start.sh"]
