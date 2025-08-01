package interfaces

import (
	"context"
	"errors"
	"time"
)

// Cache errors
var (
	ErrCacheKeyNotFound = errors.New("cache key not found")
)

// CacheService defines the interface for caching operations
type CacheService interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	Increment(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
}

// PubSubService defines the interface for publish/subscribe operations
type PubSubService interface {
	Publish(ctx context.Context, channel string, message interface{}) error
	Subscribe(ctx context.Context, channels ...string) (PubSubSubscription, error)
	Unsubscribe(ctx context.Context, channels ...string) error
}

// PubSubSubscription represents a subscription to pub/sub channels
type PubSubSubscription interface {
	Channel() <-chan *Message
	Close() error
}

// Message represents a pub/sub message
type Message struct {
	Channel string
	Payload string
}

// SessionService defines the interface for session management
type SessionService interface {
	CreateSession(ctx context.Context, userID string, metadata map[string]interface{}) (string, error)
	GetSession(ctx context.Context, sessionID string) (map[string]interface{}, error)
	UpdateSession(ctx context.Context, sessionID string, metadata map[string]interface{}) error
	DeleteSession(ctx context.Context, sessionID string) error
	GetUserSessions(ctx context.Context, userID string) ([]string, error)
}