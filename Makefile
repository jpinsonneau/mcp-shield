.PHONY: build docker-build docker-push help

# Image configuration
IMAGE_REGISTRY ?= quay.io
IMAGE_ORG ?= jpinsonn
IMAGE_NAME ?= mcp-shield
IMAGE_TAG ?= dev
IMAGE ?= $(IMAGE_REGISTRY)/$(IMAGE_ORG)/$(IMAGE_NAME):$(IMAGE_TAG)

# Build the Go binary
build:
	@echo "Building mcp-shield..."
	go build -o mcp-shield ./cmd/mcp-shield

# Build Docker image
docker-build:
	@echo "Building Docker image $(IMAGE)..."
	docker build -t $(IMAGE) .

# Push Docker image
docker-push: docker-build
	@echo "Pushing Docker image $(IMAGE)..."
	docker push $(IMAGE)

# Build and push Docker image
docker-image: docker-build docker-push

# Run locally
run: build
	@echo "Running mcp-shield..."
	./mcp-shield -listen :8080 -log-level debug

# Test
test:
	@echo "Running tests..."
	go test ./...

# Clean
clean:
	@echo "Cleaning..."
	rm -f mcp-shield
	go clean

# Help
help:
	@echo "Available targets:"
	@echo "  build        - Build the Go binary"
	@echo "  docker-build - Build the Docker image"
	@echo "  docker-push  - Build and push the Docker image"
	@echo "  run          - Build and run locally"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo ""
	@echo "Image configuration:"
	@echo "  IMAGE_REGISTRY=$(IMAGE_REGISTRY)"
	@echo "  IMAGE_ORG=$(IMAGE_ORG)"
	@echo "  IMAGE_NAME=$(IMAGE_NAME)"
	@echo "  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  IMAGE=$(IMAGE)"
	@echo ""
	@echo "Override with: make docker-build IMAGE_TAG=v1.0.0"

