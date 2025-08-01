# WebSocket Handler Implementation

This package implements WebSocket functionality for the ERP API Gateway, providing real-time messaging capabilities with Redis Pub/Sub coordination across multiple gateway instances.

## Features

- **JWT Authentication**: WebSocket connections are authenticated using JWT tokens
- **Connection Management**: Tracks active WebSocket connections with automatic cleanup
- **Redis Pub/Sub Integration**: Coordinates real-time messaging across multiple gateway instances
- **User-specific Channels**: Automatic subscription to user notification channels (`notifications:<user_id>`)
- **Channel Subscriptions**: Support for subscribing to custom channels
- **Graceful Connection Handling**: Proper connection lifecycle management with reconnection support
- **Message Types**: Support for notifications, events, heartbeats, and control messages

## Architecture

### Components

1. **Handler**: Main WebSocket handler that manages connections and Redis Pub/Sub
2. **Connection**: Individual WebSocket connection wrapper with message handling
3. **Manager**: Connection manager that tracks and coordinates all active connections

### Message Flow

```
Client WebSocket ←→ Connection ←→ Manager ←→ Handler ←→ Redis Pub/Sub
                                                    ↓
                                              Other Gateway Instances
```

## Usage

### Basic Setup

```go
import (
    "erp-api-gateway/api/ws"
    "erp-api-gateway/internal/config"
)

// Create WebSocket handler
wsHandler := ws.NewHandler(&cfg.WebSocket, redisClient, logger, jwtValidator)
defer wsHandler.Close()

// Add to Gin router
router.GET("/ws", func(c *gin.Context) {
    if err := wsHandler.HandleConnection(c.Writer, c.Request); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    }
})
```

### Authentication

WebSocket connections can be authenticated using JWT tokens in two ways:

1. **Query Parameter**: `ws://localhost:8080/ws?token=<jwt_token>`
2. **Authorization Header**: `Authorization: Bearer <jwt_token>`

### Publishing Notifications

```go
// Send notification to specific user
notification := map[string]interface{}{
    "title":   "New Message",
    "message": "You have a new message",
    "type":    "info",
}
err := wsHandler.PublishNotification(ctx, userID, notification)

// Publish event to channel
eventData := map[string]interface{}{
    "action": "user_login",
    "user_id": userID,
}
err := wsHandler.PublishEvent(ctx, "user_events", eventData)

// System-wide broadcast
broadcast := map[string]interface{}{
    "message": "System maintenance in 5 minutes",
    "type":    "warning",
}
err := wsHandler.PublishSystemBroadcast(ctx, broadcast)
```

## Message Types

### Client to Server Messages

#### Subscribe to Channel
```json
{
    "type": "subscribe",
    "data": {
        "channel": "channel_name"
    }
}
```

#### Unsubscribe from Channel
```json
{
    "type": "unsubscribe",
    "data": {
        "channel": "channel_name"
    }
}
```

#### Heartbeat
```json
{
    "type": "heartbeat"
}
```

### Server to Client Messages

#### Notification
```json
{
    "type": "notification",
    "data": {
        "title": "Notification Title",
        "message": "Notification message",
        "type": "info"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "message_id": "uuid",
    "user_id": "user123"
}
```

#### Event
```json
{
    "type": "event",
    "channel": "user_events",
    "data": {
        "action": "user_login",
        "user_id": "user123"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "message_id": "uuid"
}
```

#### Acknowledgment
```json
{
    "type": "ack",
    "data": {
        "action": "subscribe",
        "channel": "channel_name"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "message_id": "uuid"
}
```

#### Error
```json
{
    "type": "error",
    "data": {
        "error": "Error message"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "message_id": "uuid"
}
```

## Redis Pub/Sub Channels

The WebSocket handler uses the following Redis channel patterns:

- `notifications:<user_id>`: User-specific notifications
- `events:<event_type>`: Event-based notifications
- `system:broadcast`: System-wide broadcasts

## Configuration

WebSocket configuration is defined in the `WebSocketConfig` struct:

```yaml
websocket:
  read_buffer_size: 4096
  write_buffer_size: 4096
  handshake_timeout: 10s
  read_timeout: 60s
  write_timeout: 10s
  pong_timeout: 60s
  ping_period: 54s
  max_message_size: 1048576  # 1MB
  max_connections: 10000
  allowed_origins:
    - "http://localhost:3000"
    - "http://localhost:3001"
  enable_compression: true
  compression_level: 1
```

## Error Handling

The WebSocket handler implements comprehensive error handling:

- **Authentication Errors**: Invalid or missing JWT tokens
- **Connection Limits**: Maximum connection limits exceeded
- **Message Validation**: Invalid message formats
- **Redis Failures**: Graceful degradation when Redis is unavailable

## Testing

The package includes comprehensive unit tests:

```bash
go test ./api/ws/... -v
```

Tests cover:
- Handler initialization
- Authentication flows
- Message publishing
- Redis message handling
- WebSocket integration

## Performance Considerations

- **Connection Pooling**: Efficient connection management with automatic cleanup
- **Message Buffering**: Buffered channels prevent blocking on slow clients
- **Graceful Degradation**: Continues operation when Redis is unavailable
- **Memory Management**: Proper cleanup of dead connections and resources

## Security Features

- **JWT Validation**: All connections must provide valid JWT tokens
- **Origin Checking**: CORS-style origin validation for WebSocket connections
- **Rate Limiting**: Built-in protection against message flooding
- **Input Validation**: All incoming messages are validated

## Monitoring

The handler provides metrics for monitoring:

- Active connection count
- User count
- Message throughput
- Error rates

Access via the `GetConnectionCount()` method or integrate with Prometheus metrics.