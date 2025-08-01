# Configuration Management

This package provides a comprehensive configuration management system for the Go API Gateway. It supports loading configuration from multiple sources with proper validation and environment variable overrides.

## Features

- **Multiple Configuration Sources**: Load from YAML files, JSON files, or environment variables
- **Environment Variable Overrides**: Environment variables take precedence over file configuration
- **Comprehensive Validation**: Built-in validation for all configuration parameters
- **Default Values**: Sensible defaults for all configuration options
- **Type Safety**: Strong typing with proper validation tags
- **Utility Methods**: Helper methods for common configuration tasks

## Usage

### Basic Usage

```go
package main

import (
    "log"
    "go-api-gateway/internal/config"
)

func main() {
    // Load configuration with defaults and environment overrides
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Failed to load configuration: %v", err)
    }
    
    // Use configuration
    fmt.Printf("Server will run on %s:%d\n", cfg.Server.Host, cfg.Server.Port)
}
```

### Loading from Specific File

```go
// Load from a specific configuration file
cfg, err := config.LoadFromPath("config.yaml")
if err != nil {
    log.Fatalf("Failed to load configuration: %v", err)
}
```

### Using Utility Methods

```go
// Get database connection URL
dbURL := cfg.GetDatabaseURL()

// Get Redis address
redisAddr := cfg.GetRedisAddr()

// Get service addresses
authAddr := cfg.GetServiceAddr("auth")
crmAddr := cfg.GetServiceAddr("crm")

// Check environment
if cfg.IsProduction() {
    // Production-specific logic
}
```

## Configuration Sources

The configuration system loads settings in the following order (later sources override earlier ones):

1. **Default Values**: Built-in sensible defaults
2. **Configuration File**: YAML or JSON file (if specified)
3. **Environment Variables**: Environment variable overrides

### Configuration File

Set the `CONFIG_FILE` environment variable to specify a configuration file:

```bash
export CONFIG_FILE=config.yaml
```

The system supports both YAML and JSON formats. File format is auto-detected based on extension, or you can use files without extensions (the system will try both formats).

### Environment Variables

All configuration options can be overridden using environment variables. The environment variable names are specified in the struct tags:

```bash
# Server configuration
export SERVER_PORT=8080
export SERVER_HOST=0.0.0.0

# Database configuration
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=erp_gateway
export DB_USER=postgres
export DB_PASSWORD=secret

# Redis configuration
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=secret

# JWT configuration
export JWT_JWKS_URL=http://localhost:8081/.well-known/jwks.json
export JWT_ALGORITHM=RS256

# Comma-separated values for slices
export CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
export KAFKA_BROKERS=localhost:9092,localhost:9093
```

## Configuration Structure

### Server Configuration

```yaml
server:
  port: 8080                    # HTTP server port
  host: "0.0.0.0"              # HTTP server host
  read_timeout: "30s"          # Request read timeout
  write_timeout: "30s"         # Response write timeout
  shutdown_timeout: "10s"      # Graceful shutdown timeout
  cors:
    allowed_origins:           # CORS allowed origins
      - "http://localhost:3000"
    allowed_methods:           # CORS allowed methods
      - "GET"
      - "POST"
    allowed_headers:           # CORS allowed headers
      - "Authorization"
    allow_credentials: true    # CORS allow credentials
    max_age: 86400            # CORS preflight cache duration
```

### Database Configuration

```yaml
database:
  host: "localhost"           # Database host
  port: 5432                 # Database port
  name: "erp_gateway"        # Database name
  user: "postgres"           # Database user
  password: "postgres"       # Database password
  ssl_mode: "disable"        # SSL mode (disable, require, verify-ca, verify-full)
```

### Redis Configuration

```yaml
redis:
  host: "localhost"          # Redis host
  port: 6379                # Redis port
  password: ""              # Redis password (optional)
  db: 0                     # Redis database number (0-15)
  pool_size: 10             # Connection pool size
  min_idle_conns: 5         # Minimum idle connections
  dial_timeout: "5s"        # Connection timeout
  read_timeout: "3s"        # Read timeout
  write_timeout: "3s"       # Write timeout
```

### Kafka Configuration

```yaml
kafka:
  brokers:                  # Kafka broker addresses
    - "localhost:9092"
  client_id: "go-api-gateway"  # Kafka client ID
  retry_max: 3              # Maximum retry attempts
  retry_backoff: "100ms"    # Retry backoff duration
  flush_messages: 100       # Messages to buffer before flush
  flush_bytes: 1048576      # Bytes to buffer before flush (1MB)
  flush_timeout: "1s"       # Flush timeout
```

### gRPC Services Configuration

```yaml
grpc:
  auth_service:
    host: "localhost"
    port: 50051
    timeout: "10s"
    max_retries: 3
    retry_backoff: "100ms"
    circuit_breaker:
      max_failures: 5        # Max failures before opening circuit
      timeout: "60s"         # Circuit open timeout
      interval: "10s"        # Health check interval
  # Similar configuration for crm_service, hrm_service, finance_service
```

### JWT Configuration

```yaml
jwt:
  public_key_path: ""                                    # Path to RSA public key file
  jwks_url: "http://localhost:8081/.well-known/jwks.json"  # JWKS endpoint URL
  cache_ttl: "1h"                                       # Token cache TTL
  algorithm: "RS256"                                    # JWT algorithm (RS256, ES256, HS256)
  issuer: "erp-auth-service"                           # Expected token issuer
```

### Logging Configuration

```yaml
logging:
  level: "info"              # Log level (debug, info, warn, error, fatal)
  format: "json"             # Log format (json, text)
  output: "stdout"           # Log output (stdout, stderr, file)
  buffer_size: 1000          # Log buffer size
  flush_interval: "5s"       # Log flush interval
  elasticsearch:
    urls:                    # Elasticsearch URLs
      - "http://localhost:9200"
    username: ""             # Elasticsearch username (optional)
    password: ""             # Elasticsearch password (optional)
    index_name: "go-api-gateway-logs"  # Elasticsearch index name
```

## Validation

The configuration system includes comprehensive validation:

- **Port Ranges**: Validates ports are between 1-65535
- **Required Fields**: Ensures required fields are not empty
- **Enum Values**: Validates enum fields have allowed values
- **Positive Values**: Ensures numeric fields are positive where required
- **URL Formats**: Basic URL format validation
- **SSL Modes**: Validates PostgreSQL SSL modes
- **JWT Algorithms**: Validates supported JWT algorithms

## Error Handling

Configuration errors are returned with descriptive messages:

```go
cfg, err := config.Load()
if err != nil {
    // Error messages include context about what failed
    log.Fatalf("Configuration error: %v", err)
}
```

Common error scenarios:
- Invalid port numbers
- Missing required fields
- Invalid enum values
- File parsing errors
- Environment variable parsing errors

## Testing

The package includes comprehensive tests covering:
- Default value loading
- File-based configuration (YAML and JSON)
- Environment variable overrides
- Validation scenarios
- Utility methods
- Error conditions

Run tests with:
```bash
go test -v ./internal/config/
```

## Examples

See the example configuration files:
- `config.example.yaml` - YAML format example
- `config.example.json` - JSON format example

These files contain all available configuration options with comments explaining their purpose.