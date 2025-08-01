# Logging Package

This package provides structured logging functionality for the Go API Gateway, with support for Elasticsearch as the primary logging backend.

## Features

- **Structured JSON Logging**: All logs are structured in JSON format with consistent fields
- **Elasticsearch Integration**: Async batched writes to Elasticsearch for scalable log storage
- **Multiple Log Types**: Support for request logs, error logs, event logs, and metric logs
- **Async Processing**: Non-blocking log processing with configurable buffering
- **Batch Processing**: Efficient bulk writes to Elasticsearch
- **Health Monitoring**: Built-in health checks for Elasticsearch connectivity
- **Failover Support**: Multiple Elasticsearch URLs with automatic failover
- **Authentication**: Support for Elasticsearch authentication

## Components

### ElasticLogger

The main logger implementation that sends logs to Elasticsearch.

```go
// Create a new logger
config := &config.LoggingConfig{
    BufferSize:    1000,
    FlushInterval: 5 * time.Second,
    Elasticsearch: config.ElasticsearchConfig{
        URLs:      []string{"http://localhost:9200"},
        Username:  "elastic",
        Password:  "password",
        IndexName: "api-gateway-logs",
    },
}

logger, err := logging.NewElasticLogger(config)
if err != nil {
    log.Fatal(err)
}
defer logger.Close()
```

### Logging Middleware

Gin middleware for automatic request/response logging.

```go
// Create logging middleware
loggingMiddleware := middleware.NewLoggingMiddleware(logger)

// Set up Gin router with logging
router := gin.New()
router.Use(loggingMiddleware.RequestLogger())
router.Use(loggingMiddleware.ErrorLogger())
router.Use(loggingMiddleware.PanicRecovery())
```

### Structured Logger

Helper for structured logging in handlers.

```go
// Create structured logger
structuredLogger := middleware.NewStructuredLogger(logger)

// Use in handlers
func MyHandler(c *gin.Context) {
    structuredLogger.Info(c, "Processing request", map[string]interface{}{
        "endpoint": "/api/users",
        "method":   "GET",
    })
    
    if err := someOperation(); err != nil {
        structuredLogger.Error(c, "Operation failed", err, map[string]interface{}{
            "operation": "someOperation",
        })
        c.JSON(500, gin.H{"error": "internal error"})
        return
    }
    
    c.JSON(200, gin.H{"message": "success"})
}
```

## Log Types

### Request Logs

Automatically logged by the RequestLogger middleware:

```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "request_id": "req-123",
  "user_id": "user-456",
  "method": "GET",
  "path": "/api/users",
  "status_code": 200,
  "duration": 150000000,
  "user_agent": "Mozilla/5.0...",
  "remote_ip": "127.0.0.1",
  "request_size": 0,
  "response_size": 1024
}
```

### Error Logs

Logged automatically for errors and panics, or manually:

```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "request_id": "req-123",
  "user_id": "user-456",
  "level": "error",
  "message": "Database connection failed",
  "error": "connection timeout",
  "stack_trace": "...",
  "service": "go-api-gateway",
  "component": "handler"
}
```

### Event Logs

For business events:

```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "event_id": "evt-123",
  "event_type": "user_login",
  "user_id": "user-456",
  "correlation_id": "corr-789",
  "source": "go-api-gateway",
  "data": {
    "ip": "127.0.0.1",
    "user_agent": "Mozilla/5.0..."
  },
  "success": true
}
```

### Metric Logs

For performance metrics:

```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "metric_name": "response_time",
  "metric_type": "histogram",
  "value": 150.5,
  "labels": {
    "endpoint": "/api/users",
    "method": "GET"
  },
  "unit": "ms"
}
```

## Configuration

The logging system is configured through the application configuration:

```yaml
logging:
  level: info
  format: json
  output: stdout
  buffer_size: 1000
  flush_interval: 5s
  elasticsearch:
    urls:
      - http://localhost:9200
      - http://localhost:9201
    username: elastic
    password: password
    index_name: api-gateway-logs
```

## Index Management

Logs are automatically indexed in Elasticsearch with date-based index names:

- `api-gateway-logs-request-2025.01.01`
- `api-gateway-logs-error-2025.01.01`
- `api-gateway-logs-event-2025.01.01`
- `api-gateway-logs-metric-2025.01.01`

This allows for efficient log rotation and management.

## Performance Considerations

- **Async Processing**: All logging is asynchronous to avoid blocking request processing
- **Batching**: Logs are processed in batches to reduce Elasticsearch load
- **Buffering**: Configurable buffer size to handle traffic spikes
- **Connection Pooling**: HTTP client reuses connections to Elasticsearch
- **Failover**: Multiple Elasticsearch URLs for high availability

## Health Monitoring

The logger provides health check functionality:

```go
if err := logger.Health(); err != nil {
    log.Printf("Elasticsearch health check failed: %v", err)
}
```

## Error Handling

- **Buffer Full**: When the buffer is full, request/error logs are sent synchronously to prevent data loss
- **Elasticsearch Down**: Logs are dropped for events/metrics but preserved for requests/errors
- **Network Issues**: Automatic retry with multiple Elasticsearch URLs
- **Graceful Shutdown**: All buffered logs are flushed on shutdown

## Testing

The package includes comprehensive unit tests with mock Elasticsearch servers:

```bash
go test ./internal/logging -v
go test ./middleware -v -run TestLogging
```

## Best Practices

1. **Use Request IDs**: Always include request IDs for tracing
2. **Structured Fields**: Use structured fields instead of formatted messages
3. **Sensitive Data**: Never log passwords, tokens, or other sensitive data
4. **Error Context**: Include relevant context when logging errors
5. **Performance**: Use async logging for non-critical logs
6. **Monitoring**: Monitor buffer size and Elasticsearch health