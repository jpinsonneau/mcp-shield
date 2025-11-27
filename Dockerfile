# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy only source code directories needed for build
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o mcp-shield \
    ./cmd/mcp-shield

# Runtime stage
FROM alpine:latest

# Install ca-certificates and wget for HTTPS requests and health checks
RUN apk --no-cache add ca-certificates tzdata wget

# Create non-root user
RUN addgroup -g 1000 mcp-shield && \
    adduser -D -u 1000 -G mcp-shield mcp-shield

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/mcp-shield .

# Change ownership to non-root user
RUN chown -R mcp-shield:mcp-shield /app

# Switch to non-root user
USER mcp-shield

# Expose default port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz 2>/dev/null || exit 1

# Run the binary
ENTRYPOINT ["./mcp-shield"]
CMD ["-listen", ":8080"]

