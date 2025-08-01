# Redis Client Service

The Redis Client Service provides a comprehensive Redis client implementation with connection pooling, failover support, caching, pub/sub messaging, and session management capabilities.

## Features

### 1. Connection Pooling and Failover Support
- Configurable connection pool with min/max connections
- Automatic retry logic with exponential backoff
- Health check monitoring with automatic availability detection
- Graceful degradation when Redis is unavailable

### 2. Caching Interface
- Standard cache operations: GET, SET, DELETE, EXISTS
- TTL (Time To Live) support for automatic expiration
- SetNX (Set if Not Exists) for atomic operations
- Increment operations for counters
- Expire operations for setting TTL on existing keys

### 3. Pub/Sub Messaging
- Publish messages to Redis channels with JSON serialization
- Subscribe to single or multiple channels
- Buffered message channels to prevent blocking
- Automatic message processing with goroutines
- Proper subscription cleanup and unsubscribe functionality

### 4. Session Management
- Create user sessions with metadata storage
- Retrieve, update, and delete sessions
- Track multiple sessions per user
- Automatic session expiration (24-hour TTL)
- Atomic operations using Redis pipelines

### 5. Graceful Degradation
- Continues operation when Redis is unavailable
- Cache operations return appropriate errors or defaults
- Session operations handle unavailability gracefully
- Comprehensive logging for monitoring and debugging

## Usage

### Basic Setup

```go
import (
    "go-api-gateway/internal/config"
    "go-api-gateway/internal/services"
)

// Load configuration
cfg := &config.RedisConfig{
    Host:         "localhost",
    Port:         6379,
    DB:           0,
    PoolSize:     10,
    MinIdleConns: 5,
    DialTimeout:  5 * time.Second,
    ReadTimeout:  3 * time.Second,
    WriteTimeout: 3 * time.Second,
}

// Create Redis client
redisClient := services.NewRedisClient(cfg, logger)
defer redisClient.Close()
```

### Cache Operations

```go
ctx := context.Background()

// Set a value with TTL
err := redisClient.Set(ctx, "user:123", []byte("user data"), 1*time.Hour)

// Get a value
data, err := redisClient.Get(ctx, "user:123")
if err == interfaces.ErrCacheKeyNotFound {
    // Handle cache miss
}

// Check if key exists
exists, err := redisClient.Exists(ctx, "user:123")

// Delete a key
err = redisClient.Delete(ctx, "user:123")

// Atomic set if not exists
success, err := redisClient.SetNX(ctx, "lock:resource", []byte("locked"), 10*time.Minute)

// Increment counter
count, err := redisClient.Increment(ctx, "page:views")
```

### Pub/Sub Messaging

```go
ctx := context.Background()

// Subscribe to channels
subscription, err := redisClient.Subscribe(ctx, "notifications:user123", "system:broadcast")
if err != nil {
    log.Fatal(err)
}
defer subscription.Close()

// Listen for messages
go func() {
    for msg := range subscription.Channel() {
        log.Printf("Received message on %s: %s", msg.Channel, msg.Payload)
    }
}()

// Publish a message
message := map[string]interface{}{
    "type": "notification",
    "data": "Hello, World!",
}
err = redisClient.Publish(ctx, "notifications:user123", message)

// Unsubscribe from channels
err = redisClient.Unsubscribe(ctx, "notifications:user123")
```

### Session Management

```go
ctx := context.Background()

// Create a session
metadata := map[string]interface{}{
    "role":       "admin",
    "last_login": time.Now().Unix(),
    "permissions": []string{"read", "write", "delete"},
}
sessionID, err := redisClient.CreateSession(ctx, "user123", metadata)

// Get session data
sessionData, err := redisClient.GetSession(ctx, sessionID)
if err != nil {
    // Handle session not found
}

// Update session metadata
updatedMetadata := map[string]interface{}{
    "role": "super_admin",
    "last_activity": time.Now().Unix(),
}
err = redisClient.UpdateSession(ctx, sessionID, updatedMetadata)

// Get all sessions for a user
userSessions, err := redisClient.GetUserSessions(ctx, "user123")

// Delete a session
err = redisClient.DeleteSession(ctx, sessionID)
```

## Configuration

The Redis client uses the following configuration structure:

```go
type RedisConfig struct {
    Host         string        // Redis server host
    Port         int           // Redis server port
    Password     string        // Redis password (optional)
    DB           int           // Redis database number (0-15)
    PoolSize     int           // Maximum number of connections
    MinIdleConns int           // Minimum idle connections
    DialTimeout  time.Duration // Connection timeout
    ReadTimeout  time.Duration // Read operation timeout
    WriteTimeout time.Duration // Write operation timeout
}
```

### Environment Variables

The configuration can be overridden using environment variables:

- `REDIS_HOST` - Redis server host
- `REDIS_PORT` - Redis server port
- `REDIS_PASSWORD` - Redis password
- `REDIS_DB` - Redis database number
- `REDIS_POOL_SIZE` - Connection pool size
- `REDIS_MIN_IDLE_CONNS` - Minimum idle connections
- `REDIS_DIAL_TIMEOUT` - Connection timeout
- `REDIS_READ_TIMEOUT` - Read timeout
- `REDIS_WRITE_TIMEOUT` - Write timeout

## Error Handling

The Redis client implements comprehensive error handling:

### Cache Errors
- `interfaces.ErrCacheKeyNotFound` - Returned when a key doesn't exist
- Connection errors are logged and operations may be retried
- When Redis is unavailable, cache operations gracefully degrade

### Pub/Sub Errors
- Publish operations return errors when Redis is unavailable
- Subscribe operations return errors if connection fails
- Message processing errors are logged but don't stop the subscription

### Session Errors
- Session not found errors are returned for invalid session IDs
- Redis unavailability errors are returned for critical operations
- Delete operations gracefully handle non-existent sessions

## Health Monitoring

The Redis client includes built-in health monitoring:

- Periodic health checks every 30 seconds
- Automatic availability status updates
- Logging of availability state changes
- Graceful degradation when Redis becomes unavailable

## Testing

The service includes comprehensive unit tests covering:

- All cache operations (GET, SET, DELETE, EXISTS, SetNX, Increment, Expire)
- Pub/Sub functionality (publish, subscribe, unsubscribe, multiple channels)
- Session management (create, get, update, delete, user sessions)
- Graceful degradation scenarios
- Connection pooling and concurrent operations
- Health monitoring and ping functionality

Run tests with:
```bash
go test ./internal/services -v
```

## Performance Considerations

### Connection Pooling
- Configure `PoolSize` based on expected concurrent load
- Set `MinIdleConns` to maintain warm connections
- Monitor connection usage and adjust as needed

### Message Buffering
- Pub/Sub subscriptions use buffered channels (100 messages)
- Messages are dropped if buffer is full (logged as warnings)
- Consider increasing buffer size for high-throughput scenarios

### Session Storage
- Sessions use 24-hour TTL by default
- Session data is JSON-serialized for storage
- Use pipelines for atomic multi-key operations

### Graceful Degradation
- Cache misses are returned when Redis is unavailable
- Non-critical operations continue without Redis
- Critical operations (sessions, pub/sub) return errors when Redis is down

## Integration

The Redis client integrates with other gateway components:

- **Authentication Middleware**: Caches JWT validation results
- **RBAC Middleware**: Caches permission lookups
- **WebSocket Handler**: Uses pub/sub for real-time messaging
- **Session Management**: Stores user session metadata
- **Logging**: Provides structured logging for monitoring

## Monitoring and Observability

The service provides extensive logging for monitoring:

- Connection status changes
- Operation failures and retries
- Performance metrics
- Error conditions
- Graceful degradation events

All logs include contextual information for debugging and monitoring.