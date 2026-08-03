FROM golang:1.25.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the binary with CGO_ENABLED=0 for a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/template-tester ./cmd/template-tester

# Use a minimal distroless image for runtime
FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /app/bin/template-tester /app/template-tester

# Expose the default port
EXPOSE 8080

# Run the server by default
CMD ["/app/template-tester", "serve"]
