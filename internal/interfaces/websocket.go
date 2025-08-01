package interfaces

import (
	"context"
	"net/http"
	"time"
)

// WebSocketHandler defines the interface for WebSocket operations
type WebSocketHandler interface {
	HandleConnection(w http.ResponseWriter, r *http.Request) error
	BroadcastToUser(ctx context.Context, userID string, message []byte) error
	BroadcastToChannel(ctx context.Context, channel string, message []byte) error
	GetConnectionCount() int
	Close() error
}

// WebSocketConnection represents a WebSocket connection
type WebSocketConnection interface {
	GetID() string
	GetUserID() string
	GetChannels() []string
	Send(ctx context.Context, message []byte) error
	Subscribe(channel string) error
	Unsubscribe(channel string) error
	Close() error
	IsAlive() bool
}

// ConnectionManager manages WebSocket connections
type ConnectionManager interface {
	AddConnection(conn WebSocketConnection) error
	RemoveConnection(connectionID string) error
	GetConnection(connectionID string) (WebSocketConnection, bool)
	GetUserConnections(userID string) []WebSocketConnection
	GetChannelConnections(channel string) []WebSocketConnection
	BroadcastToUser(ctx context.Context, userID string, message []byte) error
	BroadcastToChannel(ctx context.Context, channel string, message []byte) error
	GetConnectionCount() int
	GetUserCount() int
	Close() error
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type      string                 `json:"type"`
	Channel   string                 `json:"channel,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	UserID    string                 `json:"user_id,omitempty"`
	MessageID string                 `json:"message_id"`
}

// WebSocketMessageType constants
const (
	MessageTypeNotification = "notification"
	MessageTypeEvent        = "event"
	MessageTypeHeartbeat    = "heartbeat"
	MessageTypeSubscribe    = "subscribe"
	MessageTypeUnsubscribe  = "unsubscribe"
	MessageTypeError        = "error"
	MessageTypeAck          = "ack"
)

// WebSocketError represents a WebSocket error
type WebSocketError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

// Error implements the error interface
func (e *WebSocketError) Error() string {
	return e.Message
}

// WebSocket error codes
const (
	WSErrorCodeInvalidMessage     = 4000
	WSErrorCodeAuthenticationFail = 4001
	WSErrorCodeUnauthorized       = 4003
	WSErrorCodeRateLimited        = 4029
	WSErrorCodeInternalError      = 4500
)