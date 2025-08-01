package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// RedisClient implements caching, pub/sub, and session management using Redis
type RedisClient struct {
	client          *redis.Client
	pubsub          *redis.PubSub
	config          *config.RedisConfig
	isAvailable     bool
	availabilityMu  sync.RWMutex
	subscriptions   map[string]*redisSubscription
	subscriptionsMu sync.RWMutex
	logger          interfaces.SimpleLogger
}

// redisSubscription wraps Redis PubSub subscription
type redisSubscription struct {
	pubsub   *redis.PubSub
	channels []string
	msgChan  chan *interfaces.Message
	closeCh  chan struct{}
	closed   bool
	mu       sync.RWMutex
}

// NewRedisClient creates a new Redis client with connection pooling and failover support
func NewRedisClient(cfg *config.RedisConfig, logger interfaces.SimpleLogger) *RedisClient {
	if logger == nil {
		logger = &defaultLogger{}
	}

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		
		// Connection pool settings for failover support
		MaxRetries:      3,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 512 * time.Millisecond,
		
		// Health check settings
		PoolTimeout: 30 * time.Second,
		IdleTimeout: 5 * time.Minute,
	})

	redisClient := &RedisClient{
		client:        client,
		config:        cfg,
		isAvailable:   true,
		subscriptions: make(map[string]*redisSubscription),
		logger:        logger,
	}

	// Start health check goroutine
	go redisClient.healthCheck()

	return redisClient
}

// healthCheck periodically checks Redis availability
func (r *RedisClient) healthCheck() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := r.client.Ping(ctx).Err()
		cancel()

		r.availabilityMu.Lock()
		wasAvailable := r.isAvailable
		r.isAvailable = (err == nil)
		r.availabilityMu.Unlock()

		if wasAvailable && !r.isAvailable {
			r.logger.LogError(context.Background(), "Redis became unavailable", map[string]interface{}{
				"error": err.Error(),
			})
		} else if !wasAvailable && r.isAvailable {
			r.logger.LogInfo(context.Background(), "Redis became available", nil)
		}
	}
}

// isRedisAvailable checks if Redis is currently available
func (r *RedisClient) isRedisAvailable() bool {
	r.availabilityMu.RLock()
	defer r.availabilityMu.RUnlock()
	return r.isAvailable
}

// CacheService implementation

// Get retrieves a value from the cache
func (r *RedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	if !r.isRedisAvailable() {
		return nil, interfaces.ErrCacheKeyNotFound
	}

	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, interfaces.ErrCacheKeyNotFound
		}
		r.logger.LogError(ctx, "Redis GET operation failed", map[string]interface{}{
			"key":   key,
			"error": err.Error(),
		})
		return nil, err
	}
	return []byte(val), nil
}

// Set stores a value in the cache with TTL
func (r *RedisClient) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if !r.isRedisAvailable() {
		r.logger.LogWarning(ctx, "Redis unavailable, skipping SET operation", map[string]interface{}{
			"key": key,
		})
		return nil // Graceful degradation
	}

	err := r.client.Set(ctx, key, value, ttl).Err()
	if err != nil {
		r.logger.LogError(ctx, "Redis SET operation failed", map[string]interface{}{
			"key":   key,
			"ttl":   ttl.String(),
			"error": err.Error(),
		})
	}
	return err
}

// Delete removes a key from the cache
func (r *RedisClient) Delete(ctx context.Context, key string) error {
	if !r.isRedisAvailable() {
		r.logger.LogWarning(ctx, "Redis unavailable, skipping DELETE operation", map[string]interface{}{
			"key": key,
		})
		return nil // Graceful degradation
	}

	err := r.client.Del(ctx, key).Err()
	if err != nil {
		r.logger.LogError(ctx, "Redis DELETE operation failed", map[string]interface{}{
			"key":   key,
			"error": err.Error(),
		})
	}
	return err
}

// Exists checks if a key exists in the cache
func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	if !r.isRedisAvailable() {
		return false, nil // Graceful degradation
	}

	count, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		r.logger.LogError(ctx, "Redis EXISTS operation failed", map[string]interface{}{
			"key":   key,
			"error": err.Error(),
		})
		return false, err
	}
	return count > 0, nil
}

// SetNX sets a key only if it doesn't exist
func (r *RedisClient) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if !r.isRedisAvailable() {
		return false, nil // Graceful degradation
	}

	result, err := r.client.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		r.logger.LogError(ctx, "Redis SETNX operation failed", map[string]interface{}{
			"key":   key,
			"ttl":   ttl.String(),
			"error": err.Error(),
		})
	}
	return result, err
}

// Increment increments a key's value
func (r *RedisClient) Increment(ctx context.Context, key string) (int64, error) {
	if !r.isRedisAvailable() {
		return 0, nil // Graceful degradation
	}

	result, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		r.logger.LogError(ctx, "Redis INCR operation failed", map[string]interface{}{
			"key":   key,
			"error": err.Error(),
		})
	}
	return result, err
}

// Expire sets a TTL on an existing key
func (r *RedisClient) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if !r.isRedisAvailable() {
		return nil // Graceful degradation
	}

	err := r.client.Expire(ctx, key, ttl).Err()
	if err != nil {
		r.logger.LogError(ctx, "Redis EXPIRE operation failed", map[string]interface{}{
			"key":   key,
			"ttl":   ttl.String(),
			"error": err.Error(),
		})
	}
	return err
}

// PubSubService implementation

// Publish publishes a message to a Redis channel
func (r *RedisClient) Publish(ctx context.Context, channel string, message interface{}) error {
	if !r.isRedisAvailable() {
		r.logger.LogError(ctx, "Redis unavailable, failed to publish message", map[string]interface{}{
			"channel": channel,
		})
		return fmt.Errorf("redis unavailable")
	}

	// Serialize message to JSON
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	err = r.client.Publish(ctx, channel, data).Err()
	if err != nil {
		r.logger.LogError(ctx, "Redis PUBLISH operation failed", map[string]interface{}{
			"channel": channel,
			"error":   err.Error(),
		})
		return err
	}

	r.logger.LogInfo(ctx, "Message published to Redis channel", map[string]interface{}{
		"channel": channel,
	})
	return nil
}

// Subscribe subscribes to one or more Redis channels
func (r *RedisClient) Subscribe(ctx context.Context, channels ...string) (interfaces.PubSubSubscription, error) {
	if !r.isRedisAvailable() {
		return nil, fmt.Errorf("redis unavailable")
	}

	pubsub := r.client.Subscribe(ctx, channels...)
	
	// Test the subscription
	_, err := pubsub.Receive(ctx)
	if err != nil {
		pubsub.Close()
		return nil, fmt.Errorf("failed to subscribe to channels: %w", err)
	}

	subscription := &redisSubscription{
		pubsub:   pubsub,
		channels: channels,
		msgChan:  make(chan *interfaces.Message, 100), // Buffered channel
		closeCh:  make(chan struct{}),
		closed:   false,
	}

	// Start message processing goroutine
	go subscription.processMessages(ctx, r.logger)

	// Store subscription for cleanup
	subscriptionKey := fmt.Sprintf("%v", channels)
	r.subscriptionsMu.Lock()
	r.subscriptions[subscriptionKey] = subscription
	r.subscriptionsMu.Unlock()

	r.logger.LogInfo(ctx, "Subscribed to Redis channels", map[string]interface{}{
		"channels": channels,
	})

	return subscription, nil
}

// Unsubscribe unsubscribes from Redis channels
func (r *RedisClient) Unsubscribe(ctx context.Context, channels ...string) error {
	subscriptionKey := fmt.Sprintf("%v", channels)
	
	r.subscriptionsMu.Lock()
	subscription, exists := r.subscriptions[subscriptionKey]
	if exists {
		delete(r.subscriptions, subscriptionKey)
	}
	r.subscriptionsMu.Unlock()

	if exists {
		subscription.Close()
		r.logger.LogInfo(ctx, "Unsubscribed from Redis channels", map[string]interface{}{
			"channels": channels,
		})
	}

	return nil
}

// SessionService implementation

// CreateSession creates a new user session
func (r *RedisClient) CreateSession(ctx context.Context, userID string, metadata map[string]interface{}) (string, error) {
	if !r.isRedisAvailable() {
		return "", fmt.Errorf("redis unavailable")
	}

	sessionID := fmt.Sprintf("session:%s:%d", userID, time.Now().UnixNano())
	sessionKey := fmt.Sprintf("sessions:%s", sessionID)
	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)

	// Add session metadata
	sessionData := map[string]interface{}{
		"user_id":    userID,
		"created_at": time.Now().Unix(),
		"metadata":   metadata,
	}

	// Serialize session data
	data, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()
	
	// Store session data with 24-hour TTL
	pipe.Set(ctx, sessionKey, data, 24*time.Hour)
	
	// Add session to user's session list
	pipe.SAdd(ctx, userSessionsKey, sessionID)
	pipe.Expire(ctx, userSessionsKey, 24*time.Hour)

	_, err = pipe.Exec(ctx)
	if err != nil {
		r.logger.LogError(ctx, "Failed to create session", map[string]interface{}{
			"user_id":    userID,
			"session_id": sessionID,
			"error":      err.Error(),
		})
		return "", err
	}

	r.logger.LogInfo(ctx, "Session created", map[string]interface{}{
		"user_id":    userID,
		"session_id": sessionID,
	})

	return sessionID, nil
}

// GetSession retrieves session data
func (r *RedisClient) GetSession(ctx context.Context, sessionID string) (map[string]interface{}, error) {
	if !r.isRedisAvailable() {
		return nil, fmt.Errorf("redis unavailable")
	}

	sessionKey := fmt.Sprintf("sessions:%s", sessionID)
	
	data, err := r.client.Get(ctx, sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		r.logger.LogError(ctx, "Failed to get session", map[string]interface{}{
			"session_id": sessionID,
			"error":      err.Error(),
		})
		return nil, err
	}

	var sessionData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return sessionData, nil
}

// UpdateSession updates session metadata
func (r *RedisClient) UpdateSession(ctx context.Context, sessionID string, metadata map[string]interface{}) error {
	if !r.isRedisAvailable() {
		return fmt.Errorf("redis unavailable")
	}

	sessionKey := fmt.Sprintf("sessions:%s", sessionID)
	
	// Get existing session data
	existingData, err := r.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Update metadata
	existingData["metadata"] = metadata
	existingData["updated_at"] = time.Now().Unix()

	// Serialize updated data
	data, err := json.Marshal(existingData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Update session with extended TTL
	err = r.client.Set(ctx, sessionKey, data, 24*time.Hour).Err()
	if err != nil {
		r.logger.LogError(ctx, "Failed to update session", map[string]interface{}{
			"session_id": sessionID,
			"error":      err.Error(),
		})
		return err
	}

	r.logger.LogInfo(ctx, "Session updated", map[string]interface{}{
		"session_id": sessionID,
	})

	return nil
}

// DeleteSession deletes a session
func (r *RedisClient) DeleteSession(ctx context.Context, sessionID string) error {
	if !r.isRedisAvailable() {
		return nil // Graceful degradation
	}

	sessionKey := fmt.Sprintf("sessions:%s", sessionID)
	
	// Get session to find user ID
	sessionData, err := r.GetSession(ctx, sessionID)
	if err != nil {
		// Session might not exist, which is fine
		return nil
	}

	userID, ok := sessionData["user_id"].(string)
	if !ok {
		return fmt.Errorf("invalid session data: missing user_id")
	}

	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()
	pipe.Del(ctx, sessionKey)
	pipe.SRem(ctx, userSessionsKey, sessionID)
	
	_, err = pipe.Exec(ctx)
	if err != nil {
		r.logger.LogError(ctx, "Failed to delete session", map[string]interface{}{
			"session_id": sessionID,
			"user_id":    userID,
			"error":      err.Error(),
		})
		return err
	}

	r.logger.LogInfo(ctx, "Session deleted", map[string]interface{}{
		"session_id": sessionID,
		"user_id":    userID,
	})

	return nil
}

// GetUserSessions retrieves all session IDs for a user
func (r *RedisClient) GetUserSessions(ctx context.Context, userID string) ([]string, error) {
	if !r.isRedisAvailable() {
		return []string{}, nil // Graceful degradation
	}

	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)
	
	sessions, err := r.client.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		r.logger.LogError(ctx, "Failed to get user sessions", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, err
	}

	return sessions, nil
}

// Close closes the Redis client and all subscriptions
func (r *RedisClient) Close() error {
	// Close all subscriptions
	r.subscriptionsMu.Lock()
	for _, subscription := range r.subscriptions {
		subscription.Close()
	}
	r.subscriptions = make(map[string]*redisSubscription)
	r.subscriptionsMu.Unlock()

	// Close main client
	return r.client.Close()
}

// Ping tests the Redis connection
func (r *RedisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// redisSubscription methods

// Channel returns the message channel
func (s *redisSubscription) Channel() <-chan *interfaces.Message {
	return s.msgChan
}

// Close closes the subscription
func (s *redisSubscription) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	close(s.closeCh)
	close(s.msgChan)
	return s.pubsub.Close()
}

// processMessages processes incoming Redis messages
func (s *redisSubscription) processMessages(ctx context.Context, logger interfaces.SimpleLogger) {
	defer func() {
		if r := recover(); r != nil {
			logger.LogError(ctx, "Panic in Redis message processing", map[string]interface{}{
				"panic": r,
			})
		}
	}()

	ch := s.pubsub.Channel()
	
	for {
		select {
		case <-s.closeCh:
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			
			s.mu.RLock()
			closed := s.closed
			s.mu.RUnlock()
			
			if closed {
				return
			}

			// Convert Redis message to interface message
			interfaceMsg := &interfaces.Message{
				Channel: msg.Channel,
				Payload: msg.Payload,
			}

			// Try to send message, but don't block if channel is full
			select {
			case s.msgChan <- interfaceMsg:
			default:
				logger.LogWarning(ctx, "Message channel full, dropping message", map[string]interface{}{
					"channel": msg.Channel,
				})
			}
		}
	}
}

// defaultLogger provides a basic logger implementation
type defaultLogger struct{}

func (l *defaultLogger) LogInfo(ctx context.Context, message string, fields map[string]interface{}) {
	log.Printf("INFO: %s %v", message, fields)
}

func (l *defaultLogger) LogWarning(ctx context.Context, message string, fields map[string]interface{}) {
	log.Printf("WARNING: %s %v", message, fields)
}

func (l *defaultLogger) LogError(ctx context.Context, message string, fields map[string]interface{}) {
	log.Printf("ERROR: %s %v", message, fields)
}