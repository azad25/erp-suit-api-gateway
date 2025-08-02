# Multi-stage Dockerfile for ERP API Gateway
# Optimized for production deployment with minimal image size

# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make \
    gcc \
    musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o gateway \
    cmd/server/main.go

# Development stage (for local development)
FROM golang:1.21-alpine AS development

RUN apk add --no-cache git ca-certificates tzdata curl

WORKDIR /app

# Install air for hot reloading
RUN go install github.com/cosmtrek/air@latest

COPY go.mod go.sum ./
RUN go mod download

COPY . .

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]

# Production stage
FROM scratch AS production

# Copy certificates and timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /app/gateway /gateway

# Copy configuration files
COPY --from=builder /app/config.yaml /app/config.yaml

# Create non-root user
USER 65534:65534

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/gateway", "healthcheck"] || exit 1

# Set entrypoint
ENTRYPOINT ["/gateway"]

# Default command
CMD ["serve"]