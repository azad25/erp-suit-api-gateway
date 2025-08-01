# Go API Gateway Makefile

.PHONY: build run test clean deps fmt lint

# Build the application
build:
	go build -o bin/server cmd/server/main.go

# Run the application
run:
	go run cmd/server/main.go

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Download dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run

# Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run the server with hot reload (requires air)
dev:
	air

# Build Docker image
docker-build:
	docker build -t go-api-gateway:latest .

# Run with Docker Compose
docker-up:
	docker-compose up -d

# Stop Docker Compose
docker-down:
	docker-compose down

# View logs
logs:
	docker-compose logs -f go-api-gateway

# Health check
health:
	curl -f http://localhost:8080/health || exit 1

# Ready check
ready:
	curl -f http://localhost:8080/ready || exit 1