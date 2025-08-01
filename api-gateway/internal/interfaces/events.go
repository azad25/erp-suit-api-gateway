package interfaces

import (
	"context"
	"time"
)

// EventPublisher defines the interface for publishing events
type EventPublisher interface {
	PublishEvent(ctx context.Context, event Event) error
	PublishUserEvent(ctx context.Context, userID string, event Event) error
	PublishBatch(ctx context.Context, events []Event) error
	Close() error
}

// Event represents a business event
type Event struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"`
	UserID        string                 `json:"user_id,omitempty"`
	Data          map[string]interface{} `json:"data"`
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id"`
	Source        string                 `json:"source"`
	Version       string                 `json:"version"`
}

// EventType constants for common business events
const (
	EventTypeUserLoggedIn    = "user.logged_in"
	EventTypeUserRegistered  = "user.registered"
	EventTypeUserLoggedOut   = "user.logged_out"
	EventTypeTokenRefreshed  = "user.token_refreshed"
	EventTypeAPIRequest      = "api.request"
	EventTypeAPIError        = "api.error"
	EventTypeSystemAlert     = "system.alert"
)

// EventHandler defines the interface for handling events
type EventHandler interface {
	HandleEvent(ctx context.Context, event Event) error
	GetEventTypes() []string
}

// EventBus defines the interface for event bus operations
type EventBus interface {
	Subscribe(eventType string, handler EventHandler) error
	Unsubscribe(eventType string, handler EventHandler) error
	Publish(ctx context.Context, event Event) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}