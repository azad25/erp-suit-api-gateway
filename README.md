# Go API Gateway

A high-performance, enterprise-grade API Gateway built in Go that serves as the central entry point for the ERP system.

## Project Structur e

```
go-api-gateway/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── api/
│   ├── rest/                    # REST API handlers
│   └── graphql/                 # GraphQL handlers
├── middleware/                  # HTTP middleware components
├── service/                     # Service layer implementations
├── internal/
│   ├── config/
│   │   └── config.go           # Configuration management
│   ├── container/
│   │   └── container.go        # Dependency injection container
│   ├── interfaces/
│   │   ├── auth.go             # Authentication interfaces
│   │   ├── cache.go            # Caching interfaces
│   │   ├── events.go           # Event publishing interfaces
│   │   └── logging.go          # Logging interfaces
│   └── server/
│       └── server.go           # HTTP server implementation
├── proto/                      # Protocol buffer definitions
├── test/                       # Test files
├── go.mod                      # Go module definition
└── README.md                   # This file
```

## Features

- **Clean Architecture**: Follows clean architecture principles with clear separation of concerns
- **Dependency Injection**: Uses Uber FX for dependency injection and lifecycle management
- **Interface-Driven Design**: Core functionality defined through interfaces for testability
- **Configuration Management**: Flexible configuration with YAML files and environment variables
- **Health Checks**: Built-in health and readiness endpoints
- **Graceful Shutdown**: Proper shutdown handling with connection draining

## Core Interfaces

### Authentication (`internal/interfaces/auth.go`)
- `JWTValidator`: JWT token validation with JWKS support
- `AuthService`: Authentication operations
- `Claims`: JWT token claims structure

### Caching (`internal/interfaces/cache.go`)
- `CacheService`: Redis caching operations
- `PubSubService`: Publish/subscribe messaging
- `SessionService`: Session management

### Events (`internal/interfaces/events.go`)
- `EventPublisher`: Business event publishing to Kafka
- `EventHandler`: Event handling interface
- `EventBus`: Event bus operations

### Logging (`internal/interfaces/logging.go`)
- `Logger`: Structured logging to Elasticsearch
- Various log entry types (Request, Error, Event, Metric)

## Getting Started

1. **Install Dependencies**:
   ```bash
   go mod tidy
   ```

2. **Run the Server**:
   ```bash
   go run cmd/server/main.go
   ```

3. **Health Check**:
   ```bash
   curl http://localhost:8080/health
   ```

## Configuration

The application supports configuration through:
- YAML configuration files (set `CONFIG_FILE` environment variable)
- Environment variables
- Default values

Key configuration sections:
- `server`: HTTP server settings
- `redis`: Redis connection settings
- `kafka`: Kafka producer settings
- `grpc`: gRPC service endpoints
- `jwt`: JWT validation settings
- `logging`: Logging configuration

## Development

This project follows Go best practices:
- Clean architecture with dependency injection
- Interface-driven design for testability
- Comprehensive error handling
- Structured logging
- Configuration management
- Graceful shutdown

## Next Steps

The following components will be implemented in subsequent tasks:
1. Configuration management system
2. JWT validation and authentication middleware
3. RBAC middleware
4. Structured logging system
5. Redis client service
6. Kafka producer service
7. gRPC client service
8. REST API handlers
9. WebSocket handler
10. GraphQL server
11. Monitoring and observability
12. Testing suite
13. Docker containerization
14. Kubernetes deployment manifests