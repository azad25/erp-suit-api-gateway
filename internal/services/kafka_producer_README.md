# Kafka Producer Service

The Kafka Producer Service provides a robust, production-ready implementation for publishing business events to Apache Kafka with comprehensive error handling, retry logic, and dead letter queue support.

## Features

- **Async Event Publishing**: Non-blocking event publishing with configurable batching
- **Retry Logic**: Exponential backoff retry mechanism for transient failures
- **Dead Letter Queue**: Failed messages are sent to a dead letter queue for later analysis
- **Correlation ID Tracking**: Full event tracing support with correlation IDs
- **Topic Mapping**: Configurable event type to Kafka topic mapping
- **Health Checks**: Built-in health check functionality
- **Graceful Shutdown**: Proper resource cleanup and connection draining
- **Comprehensive Testing**: Full unit test coverage with mock support

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───▶│  Kafka Producer  │───▶│  Kafka Cluster  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Dead Letter Queue│
                       └──────────────────┘
```

## Configuration

The Kafka producer is configured through the `config.KafkaConfig` struct:

```go
type KafkaConfig struct {
    Brokers       []string      // Kafka broker addresses
    ClientID      string        // Client identifier
    RetryMax      int           // Maximum retry attempts
    RetryBackoff  time.Duration // Retry backoff duration
    FlushMessages int           // Batch size for flushing
    FlushBytes    int           // Byte threshold for flushing
    FlushTimeout  time.Duration // Time threshold for flushing
}
```

### Environment Variables

```bash
KAFKA_BROKERS=localhost:9092,localhost:9093
KAFKA_CLIENT_ID=go-api-gateway
KAFKA_RETRY_MAX=3
KAFKA_RETRY_BACKOFF=100ms
KAFKA_FLUSH_MESSAGES=100
KAFKA_FLUSH_BYTES=1048576
KAFKA_FLUSH_TIMEOUT=1s
```

## Usage

### Basic Usage

```go
// Create producer
cfg := &config.KafkaConfig{
    Brokers:       []string{"localhost:9092"},
    ClientID:      "my-service",
    RetryMax:      3,
    RetryBackoff:  100 * time.Millisecond,
    FlushMessages: 100,
    FlushBytes:    1024 * 1024,
    FlushTimeout:  1 * time.Second,
}

producer, err := services.NewKafkaProducer(cfg)
if err != nil {
    log.Fatal(err)
}
defer producer.Close()

// Create event builder
builder := events.NewEventBuilder("my-service", "1.0")
builder.WithCorrelationID("correlation-123")

// Publish event
event := builder.BuildUserLoggedInEvent(events.UserLoggedInEvent{
    UserID:      "user-123",
    Email:       "user@example.com",
    LoginTime:   time.Now().UTC(),
    SessionID:   "session-456",
    LoginMethod: "password",
})

err = producer.PublishEvent(context.Background(), event)
if err != nil {
    log.Printf("Failed to publish event: %v", err)
}
```

### Batch Publishing

```go
events := []interfaces.Event{
    builder.BuildUserLoggedInEvent(loginData1),
    builder.BuildUserLoggedInEvent(loginData2),
    builder.BuildAPIRequestEvent(apiData),
}

err := producer.PublishBatch(context.Background(), events)
if err != nil {
    log.Printf("Failed to publish batch: %v", err)
}
```

### Health Checks

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

if err := producer.HealthCheck(ctx); err != nil {
    log.Printf("Kafka producer unhealthy: %v", err)
}
```

## Event Types and Topics

The producer automatically maps event types to Kafka topics:

| Event Type | Default Topic |
|------------|---------------|
| `user.logged_in` | `user-events` |
| `user.registered` | `user-events` |
| `user.logged_out` | `user-events` |
| `user.token_refreshed` | `auth-events` |
| `api.request` | `api-events` |
| `api.error` | `error-events` |
| `system.alert` | `system-events` |
| Unknown types | `default-events` |

### Custom Topic Mapping

```go
producer.SetTopicMapping("custom.event", "custom-topic")
```

## Business Event Models

### User Events

```go
// User login event
loginEvent := builder.BuildUserLoggedInEvent(events.UserLoggedInEvent{
    UserID:      "user-123",
    Email:       "user@example.com",
    IPAddress:   "192.168.1.1",
    UserAgent:   "Mozilla/5.0...",
    LoginTime:   time.Now().UTC(),
    SessionID:   "session-456",
    RememberMe:  true,
    LoginMethod: "password",
    DeviceInfo:  "iPhone 12",
    Location:    "New York, NY",
})

// User registration event
regEvent := builder.BuildUserRegisteredEvent(events.UserRegisteredEvent{
    UserID:             "user-456",
    Email:              "newuser@example.com",
    FirstName:          "John",
    LastName:           "Doe",
    RegistrationTime:   time.Now().UTC(),
    IPAddress:          "192.168.1.2",
    RegistrationSource: "web",
    EmailVerified:      false,
    OrganizationID:     "org-123",
})
```

### API Events

```go
// API request event
apiEvent := builder.BuildAPIRequestEvent(events.APIRequestEvent{
    RequestID:    "req-123",
    UserID:       "user-123",
    Method:       "POST",
    Path:         "/api/auth/login",
    StatusCode:   200,
    Duration:     150 * time.Millisecond,
    IPAddress:    "192.168.1.1",
    RequestTime:  time.Now().UTC(),
    ResponseSize: 1024,
    RequestSize:  512,
})

// API error event
errorEvent := builder.BuildAPIErrorEvent(events.APIErrorEvent{
    RequestID:    "req-456",
    Method:       "POST",
    Path:         "/api/auth/login",
    StatusCode:   400,
    ErrorType:    "validation_error",
    ErrorMessage: "Invalid credentials",
    ErrorCode:    "AUTH_001",
    ErrorTime:    time.Now().UTC(),
})
```

### System Events

```go
// System alert event
alertEvent := builder.BuildSystemAlertEvent(events.SystemAlertEvent{
    AlertID:   "alert-123",
    AlertType: "error",
    Service:   "api-gateway",
    Component: "auth-middleware",
    Message:   "High error rate detected",
    Severity:  "high",
    AlertTime: time.Now().UTC(),
    Metadata: map[string]interface{}{
        "error_rate": 0.15,
        "threshold":  0.10,
    },
    Resolved: false,
})
```

## Error Handling

### Retry Logic

The producer implements exponential backoff retry for transient errors:

- **Retryable Errors**: Network issues, leader not available, request timeouts
- **Non-Retryable Errors**: Invalid message format, authentication failures
- **Max Retries**: Configurable (default: 3)
- **Backoff**: Exponential with jitter (default: 100ms base)

### Dead Letter Queue

Failed messages are automatically sent to a dead letter queue:

```json
{
  "event": { /* original event */ },
  "topic": "original-topic",
  "failure_reason": "broker not available",
  "attempt_count": 3,
  "first_attempt": "2024-01-15T10:00:00Z",
  "last_attempt": "2024-01-15T10:01:30Z"
}
```

## Monitoring

### Metrics

The producer exposes the following metrics:

- `kafka_messages_sent_total`: Total messages sent
- `kafka_messages_failed_total`: Total messages failed
- `kafka_dead_letter_queue_size`: Current dead letter queue size
- `kafka_retry_attempts_total`: Total retry attempts

### Health Checks

```go
stats := producer.GetStats()
fmt.Printf("Dead Letter Queue Size: %v\n", stats["dead_letter_queue_size"])
fmt.Printf("Is Closed: %v\n", stats["is_closed"])
```

## Performance Considerations

### Batching

Configure batching parameters for optimal performance:

```go
cfg.FlushMessages = 100    // Batch size
cfg.FlushBytes = 1024*1024 // 1MB batch size
cfg.FlushTimeout = 1*time.Second // Max wait time
```

### Connection Pooling

The producer uses connection pooling internally:

- **Max Open Requests**: 1 (required for idempotent producer)
- **Compression**: Snappy compression enabled
- **Idempotent**: Enabled for exactly-once semantics

### Memory Management

- **Buffer Size**: Configurable dead letter queue buffer
- **Async Processing**: Non-blocking event publishing
- **Graceful Shutdown**: Proper resource cleanup

## Testing

### Unit Tests

```bash
go test ./internal/services -v -run TestKafkaProducer
```

### Integration Tests

```bash
go test ./internal/services -v -run TestKafkaProducer_Integration
```

### Benchmarks

```bash
go test ./internal/services -bench=BenchmarkKafkaProducer -benchmem
```

## Production Deployment

### Docker Configuration

```dockerfile
ENV KAFKA_BROKERS=kafka-1:9092,kafka-2:9092,kafka-3:9092
ENV KAFKA_CLIENT_ID=go-api-gateway-prod
ENV KAFKA_RETRY_MAX=5
ENV KAFKA_FLUSH_MESSAGES=1000
ENV KAFKA_FLUSH_BYTES=10485760
```

### Kubernetes Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kafka-config
data:
  KAFKA_BROKERS: "kafka-1:9092,kafka-2:9092,kafka-3:9092"
  KAFKA_CLIENT_ID: "go-api-gateway"
  KAFKA_RETRY_MAX: "5"
  KAFKA_FLUSH_MESSAGES: "1000"
```

## Troubleshooting

### Common Issues

1. **Connection Failures**
   - Check broker addresses and network connectivity
   - Verify Kafka cluster is running and accessible

2. **High Dead Letter Queue Size**
   - Check Kafka cluster health
   - Review error logs for failure patterns
   - Consider increasing retry limits

3. **Performance Issues**
   - Adjust batching parameters
   - Monitor connection pool usage
   - Check network latency to Kafka brokers

### Debug Logging

Enable debug logging to troubleshoot issues:

```go
// Enable debug logging in your application
log.SetLevel(log.DebugLevel)
```

## Security

### Authentication

Configure SASL authentication:

```go
// SASL configuration would be added to the Sarama config
saramaConfig.Net.SASL.Enable = true
saramaConfig.Net.SASL.Mechanism = sarama.SASLTypePlaintext
saramaConfig.Net.SASL.User = "username"
saramaConfig.Net.SASL.Password = "password"
```

### TLS

Enable TLS encryption:

```go
saramaConfig.Net.TLS.Enable = true
saramaConfig.Net.TLS.Config = &tls.Config{
    InsecureSkipVerify: false,
}
```

## Contributing

1. Add new event types to `internal/events/models.go`
2. Update topic mappings in `setupTopicMappings()`
3. Add comprehensive tests for new functionality
4. Update documentation and examples

## License

This code is part of the Go API Gateway project and follows the same license terms.