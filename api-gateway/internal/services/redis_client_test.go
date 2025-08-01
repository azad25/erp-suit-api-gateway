package services

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// mockLogger implements SimpleLogger for testing
type mockLogger struct {
	infos    []logEntry
	warnings []logEntry
	errors   []logEntry
}

type logEntry struct {
	message string
	fields  map[string]interface{}
}

func (m *mockLogger) LogInfo(ctx context.Context, message string, fields map[string]interface{}) {
	m.infos = append(m.infos, logEntry{message: message, fields: fields})
}

func (m *mockLogger) LogWarning(ctx context.Context, message string, fields map[string]interface{}) {
	m.warnings = append(m.warnings, logEntry{message: message, fields: fields})
}

func (m *mockLogger) LogError(ctx context.Context, message string, fields map[string]interface{}) {
	m.errors = append(m.errors, logEntry{message: message, fields: fields})
}

func setupTestRedis(t *testing.T) (*RedisClient, *miniredis.Miniredis, *mockLogger) {
	// Start mini Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)

	logger := &mockLogger{}
	
	cfg := &config.RedisConfig{
		Host:         "localhost",
		Port:         6379, // Will be overridden by miniredis
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 5,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	// Create Redis client with miniredis address
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
		DB:   cfg.DB,
	})

	redisClient := &RedisClient{
		client:        client,
		config:        cfg,
		isAvailable:   true,
		subscriptions: make(map[string]*redisSubscription),
		logger:        logger,
	}

	return redisClient, mr, logger
}

func TestRedisClient_CacheOperations(t *testing.T) {
	redisClient, mr, logger := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	ctx := context.Background()

	t.Run("Set and Get", func(t *testing.T) {
		key := "test:key"
		value := []byte("test value")
		ttl := 1 * time.Hour

		// Set value
		err := redisClient.Set(ctx, key, value, ttl)
		assert.NoError(t, err)

		// Get value
		result, err := redisClient.Get(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		result, err := redisClient.Get(ctx, "non:existent")
		assert.Equal(t, interfaces.ErrCacheKeyNotFound, err)
		assert.Nil(t, result)
	})

	t.Run("Delete key", func(t *testing.T) {
		key := "test:delete"
		value := []byte("delete me")

		// Set value
		err := redisClient.Set(ctx, key, value, 1*time.Hour)
		assert.NoError(t, err)

		// Verify it exists
		exists, err := redisClient.Exists(ctx, key)
		assert.NoError(t, err)
		assert.True(t, exists)

		// Delete key
		err = redisClient.Delete(ctx, key)
		assert.NoError(t, err)

		// Verify it's gone
		exists, err = redisClient.Exists(ctx, key)
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("SetNX operations", func(t *testing.T) {
		key := "test:setnx"
		value := []byte("first value")
		ttl := 1 * time.Hour

		// First SetNX should succeed
		result, err := redisClient.SetNX(ctx, key, value, ttl)
		assert.NoError(t, err)
		assert.True(t, result)

		// Second SetNX should fail (key exists)
		result, err = redisClient.SetNX(ctx, key, []byte("second value"), ttl)
		assert.NoError(t, err)
		assert.False(t, result)

		// Value should still be the first one
		retrieved, err := redisClient.Get(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, value, retrieved)
	})

	t.Run("Increment operations", func(t *testing.T) {
		key := "test:counter"

		// First increment
		result, err := redisClient.Increment(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), result)

		// Second increment
		result, err = redisClient.Increment(ctx, key)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), result)
	})

	t.Run("Expire operations", func(t *testing.T) {
		key := "test:expire"
		value := []byte("expire me")

		// Set value without TTL
		err := redisClient.Set(ctx, key, value, 0)
		assert.NoError(t, err)

		// Set expiration
		err = redisClient.Expire(ctx, key, 1*time.Second)
		assert.NoError(t, err)

		// Key should exist initially
		exists, err := redisClient.Exists(ctx, key)
		assert.NoError(t, err)
		assert.True(t, exists)

		// Fast forward time in miniredis
		mr.FastForward(2 * time.Second)

		// Key should be expired
		exists, err = redisClient.Exists(ctx, key)
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	// Verify no errors were logged during successful operations
	assert.Empty(t, logger.errors)
}

func TestRedisClient_PubSub(t *testing.T) {
	redisClient, mr, _ := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	ctx := context.Background()

	t.Run("Publish and Subscribe", func(t *testing.T) {
		channel := "test:channel"
		message := map[string]interface{}{
			"type": "test",
			"data": "hello world",
		}

		// Subscribe to channel
		subscription, err := redisClient.Subscribe(ctx, channel)
		assert.NoError(t, err)
		assert.NotNil(t, subscription)

		// Give subscription time to establish
		time.Sleep(100 * time.Millisecond)

		// Publish message
		err = redisClient.Publish(ctx, channel, message)
		assert.NoError(t, err)

		// Receive message
		select {
		case msg := <-subscription.Channel():
			assert.Equal(t, channel, msg.Channel)
			
			// Unmarshal and verify message
			var receivedMessage map[string]interface{}
			err := json.Unmarshal([]byte(msg.Payload), &receivedMessage)
			assert.NoError(t, err)
			assert.Equal(t, message, receivedMessage)
			
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for message")
		}

		// Close subscription
		err = subscription.Close()
		assert.NoError(t, err)
	})

	t.Run("Multiple channels subscription", func(t *testing.T) {
		channels := []string{"test:channel1", "test:channel2"}
		
		// Subscribe to multiple channels
		subscription, err := redisClient.Subscribe(ctx, channels...)
		assert.NoError(t, err)
		assert.NotNil(t, subscription)

		time.Sleep(100 * time.Millisecond)

		// Publish to first channel
		message1 := map[string]interface{}{"channel": "1"}
		err = redisClient.Publish(ctx, channels[0], message1)
		assert.NoError(t, err)

		// Publish to second channel
		message2 := map[string]interface{}{"channel": "2"}
		err = redisClient.Publish(ctx, channels[1], message2)
		assert.NoError(t, err)

		// Receive both messages
		receivedMessages := make(map[string]map[string]interface{})
		
		for i := 0; i < 2; i++ {
			select {
			case msg := <-subscription.Channel():
				var receivedMessage map[string]interface{}
				err := json.Unmarshal([]byte(msg.Payload), &receivedMessage)
				assert.NoError(t, err)
				receivedMessages[msg.Channel] = receivedMessage
				
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for message")
			}
		}

		assert.Equal(t, message1, receivedMessages[channels[0]])
		assert.Equal(t, message2, receivedMessages[channels[1]])

		err = subscription.Close()
		assert.NoError(t, err)
	})

	t.Run("Unsubscribe", func(t *testing.T) {
		channels := []string{"test:unsubscribe"}
		
		// Subscribe
		subscription, err := redisClient.Subscribe(ctx, channels...)
		assert.NoError(t, err)

		// Unsubscribe
		err = redisClient.Unsubscribe(ctx, channels...)
		assert.NoError(t, err)

		// Subscription should be closed
		select {
		case _, ok := <-subscription.Channel():
			assert.False(t, ok, "Channel should be closed")
		case <-time.After(1 * time.Second):
			// Timeout is acceptable here
		}
	})
}

func TestRedisClient_SessionManagement(t *testing.T) {
	redisClient, mr, logger := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	ctx := context.Background()

	t.Run("Create and Get Session", func(t *testing.T) {
		userID := "user123"
		metadata := map[string]interface{}{
			"role":       "admin",
			"last_login": float64(time.Now().Unix()), // Use float64 for JSON compatibility
		}

		// Create session
		sessionID, err := redisClient.CreateSession(ctx, userID, metadata)
		assert.NoError(t, err)
		assert.NotEmpty(t, sessionID)
		assert.Contains(t, sessionID, userID)

		// Get session
		sessionData, err := redisClient.GetSession(ctx, sessionID)
		assert.NoError(t, err)
		assert.Equal(t, userID, sessionData["user_id"])
		assert.Equal(t, metadata, sessionData["metadata"])
		assert.NotNil(t, sessionData["created_at"])
	})

	t.Run("Update Session", func(t *testing.T) {
		userID := "user456"
		initialMetadata := map[string]interface{}{
			"role": "user",
		}

		// Create session
		sessionID, err := redisClient.CreateSession(ctx, userID, initialMetadata)
		assert.NoError(t, err)

		// Update session
		updatedMetadata := map[string]interface{}{
			"role":        "admin",
			"permissions": []interface{}{"read", "write"}, // Use []interface{} for JSON compatibility
		}
		err = redisClient.UpdateSession(ctx, sessionID, updatedMetadata)
		assert.NoError(t, err)

		// Verify update
		sessionData, err := redisClient.GetSession(ctx, sessionID)
		assert.NoError(t, err)
		assert.Equal(t, updatedMetadata, sessionData["metadata"])
		assert.NotNil(t, sessionData["updated_at"])
	})

	t.Run("Delete Session", func(t *testing.T) {
		userID := "user789"
		metadata := map[string]interface{}{"role": "user"}

		// Create session
		sessionID, err := redisClient.CreateSession(ctx, userID, metadata)
		assert.NoError(t, err)

		// Verify session exists
		_, err = redisClient.GetSession(ctx, sessionID)
		assert.NoError(t, err)

		// Delete session
		err = redisClient.DeleteSession(ctx, sessionID)
		assert.NoError(t, err)

		// Verify session is gone
		_, err = redisClient.GetSession(ctx, sessionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})

	t.Run("Get User Sessions", func(t *testing.T) {
		userID := "user_multi"
		
		// Create multiple sessions for the same user
		sessionIDs := make([]string, 3)
		for i := 0; i < 3; i++ {
			metadata := map[string]interface{}{"session": i}
			sessionID, err := redisClient.CreateSession(ctx, userID, metadata)
			assert.NoError(t, err)
			sessionIDs[i] = sessionID
		}

		// Get all user sessions
		userSessions, err := redisClient.GetUserSessions(ctx, userID)
		assert.NoError(t, err)
		assert.Len(t, userSessions, 3)

		// Verify all session IDs are present
		for _, sessionID := range sessionIDs {
			assert.Contains(t, userSessions, sessionID)
		}
	})

	t.Run("Get non-existent session", func(t *testing.T) {
		_, err := redisClient.GetSession(ctx, "non-existent-session")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})

	// Verify no errors were logged during successful operations
	assert.Empty(t, logger.errors)
}

func TestRedisClient_GracefulDegradation(t *testing.T) {
	redisClient, mr, logger := setupTestRedis(t)
	defer redisClient.Close()

	ctx := context.Background()

	// Simulate Redis being unavailable
	mr.Close()
	redisClient.isAvailable = false

	t.Run("Cache operations with Redis unavailable", func(t *testing.T) {
		// Set should not return error (graceful degradation)
		err := redisClient.Set(ctx, "test:key", []byte("value"), 1*time.Hour)
		assert.NoError(t, err)

		// Get should return not found
		_, err = redisClient.Get(ctx, "test:key")
		assert.Equal(t, interfaces.ErrCacheKeyNotFound, err)

		// Delete should not return error
		err = redisClient.Delete(ctx, "test:key")
		assert.NoError(t, err)

		// Exists should return false
		exists, err := redisClient.Exists(ctx, "test:key")
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("PubSub operations with Redis unavailable", func(t *testing.T) {
		// Publish should return error
		err := redisClient.Publish(ctx, "test:channel", "message")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis unavailable")

		// Subscribe should return error
		_, err = redisClient.Subscribe(ctx, "test:channel")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis unavailable")
	})

	t.Run("Session operations with Redis unavailable", func(t *testing.T) {
		// CreateSession should return error
		_, err := redisClient.CreateSession(ctx, "user123", map[string]interface{}{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis unavailable")

		// GetSession should return error
		_, err = redisClient.GetSession(ctx, "session123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis unavailable")

		// UpdateSession should return error
		err = redisClient.UpdateSession(ctx, "session123", map[string]interface{}{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis unavailable")

		// DeleteSession should not return error (graceful degradation)
		err = redisClient.DeleteSession(ctx, "session123")
		assert.NoError(t, err)

		// GetUserSessions should return empty slice
		sessions, err := redisClient.GetUserSessions(ctx, "user123")
		assert.NoError(t, err)
		assert.Empty(t, sessions)
	})

	// Verify warnings were logged for graceful degradation
	assert.NotEmpty(t, logger.warnings)
}

func TestRedisClient_ConnectionPooling(t *testing.T) {
	redisClient, mr, _ := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	ctx := context.Background()

	// Test concurrent operations to verify connection pooling
	t.Run("Concurrent operations", func(t *testing.T) {
		const numGoroutines = 50
		const numOperations = 10

		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()
				
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("concurrent:test:%d:%d", id, j)
					value := []byte(fmt.Sprintf("value-%d-%d", id, j))

					// Set value
					err := redisClient.Set(ctx, key, value, 1*time.Hour)
					assert.NoError(t, err)

					// Get value
					result, err := redisClient.Get(ctx, key)
					assert.NoError(t, err)
					assert.Equal(t, value, result)

					// Delete value
					err = redisClient.Delete(ctx, key)
					assert.NoError(t, err)
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("Timeout waiting for concurrent operations")
			}
		}
	})
}

func TestRedisClient_Ping(t *testing.T) {
	redisClient, mr, _ := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	ctx := context.Background()

	t.Run("Ping successful", func(t *testing.T) {
		err := redisClient.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("Ping failed", func(t *testing.T) {
		mr.Close()
		err := redisClient.Ping(ctx)
		assert.Error(t, err)
	})
}