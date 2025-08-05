package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// CacheManager handles Redis caching operations
type CacheManager struct {
	client *redis.Client
	ctx    context.Context
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	DefaultTTL time.Duration
	MaxRetries int
}

// CacheItem represents a cached item with metadata
type CacheItem struct {
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
	TTL       int64       `json:"ttl"`
	Version   string      `json:"version,omitempty"`
}

// NewCacheManager creates a new cache manager
func NewCacheManager(client *redis.Client) *CacheManager {
	return &CacheManager{
		client: client,
		ctx:    context.Background(),
	}
}

// Set stores data in cache with TTL
func (c *CacheManager) Set(key string, data interface{}, ttl time.Duration) error {
	item := CacheItem{
		Data:      data,
		Timestamp: time.Now().Unix(),
		TTL:       int64(ttl.Seconds()),
	}

	jsonData, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal cache item: %w", err)
	}

	return c.client.Set(c.ctx, key, jsonData, ttl).Err()
}

// Get retrieves data from cache
func (c *CacheManager) Get(key string, dest interface{}) (bool, error) {
	val, err := c.client.Get(c.ctx, key).Result()
	if err == redis.Nil {
		return false, nil // Cache miss
	}
	if err != nil {
		return false, fmt.Errorf("failed to get cache item: %w", err)
	}

	var item CacheItem
	if err := json.Unmarshal([]byte(val), &item); err != nil {
		return false, fmt.Errorf("failed to unmarshal cache item: %w", err)
	}

	// Check if cache is still valid
	if time.Now().Unix()-item.Timestamp > item.TTL {
		c.Delete(key) // Clean up expired cache
		return false, nil
	}

	// Marshal and unmarshal to convert to destination type
	dataBytes, err := json.Marshal(item.Data)
	if err != nil {
		return false, fmt.Errorf("failed to marshal cache data: %w", err)
	}

	if err := json.Unmarshal(dataBytes, dest); err != nil {
		return false, fmt.Errorf("failed to unmarshal to destination: %w", err)
	}

	return true, nil
}

// Delete removes item from cache
func (c *CacheManager) Delete(key string) error {
	return c.client.Del(c.ctx, key).Err()
}

// DeletePattern removes all keys matching pattern
func (c *CacheManager) DeletePattern(pattern string) error {
	keys, err := c.client.Keys(c.ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return c.client.Del(c.ctx, keys...).Err()
	}

	return nil
}

// Exists checks if key exists in cache
func (c *CacheManager) Exists(key string) (bool, error) {
	count, err := c.client.Exists(c.ctx, key).Result()
	return count > 0, err
}

// SetWithVersion stores data with version for cache invalidation
func (c *CacheManager) SetWithVersion(key string, data interface{}, ttl time.Duration, version string) error {
	item := CacheItem{
		Data:      data,
		Timestamp: time.Now().Unix(),
		TTL:       int64(ttl.Seconds()),
		Version:   version,
	}

	jsonData, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal cache item: %w", err)
	}

	return c.client.Set(c.ctx, key, jsonData, ttl).Err()
}

// GetWithVersion retrieves data and checks version
func (c *CacheManager) GetWithVersion(key string, dest interface{}, expectedVersion string) (bool, error) {
	val, err := c.client.Get(c.ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get cache item: %w", err)
	}

	var item CacheItem
	if err := json.Unmarshal([]byte(val), &item); err != nil {
		return false, fmt.Errorf("failed to unmarshal cache item: %w", err)
	}

	// Check version mismatch
	if item.Version != "" && expectedVersion != "" && item.Version != expectedVersion {
		c.Delete(key) // Invalidate outdated cache
		return false, nil
	}

	// Check TTL
	if time.Now().Unix()-item.Timestamp > item.TTL {
		c.Delete(key)
		return false, nil
	}

	dataBytes, err := json.Marshal(item.Data)
	if err != nil {
		return false, fmt.Errorf("failed to marshal cache data: %w", err)
	}

	if err := json.Unmarshal(dataBytes, dest); err != nil {
		return false, fmt.Errorf("failed to unmarshal to destination: %w", err)
	}

	return true, nil
}

// Cache key generators
func UserCacheKey(userID string) string {
	return fmt.Sprintf("user:profile:%s", userID)
}

func UserPermissionsCacheKey(userID string) string {
	return fmt.Sprintf("user:permissions:%s", userID)
}

func SessionCacheKey(sessionID string) string {
	return fmt.Sprintf("session:%s", sessionID)
}

func ConfigCacheKey() string {
	return "system:config"
}

func DashboardMetricsCacheKey(userID string) string {
	return fmt.Sprintf("dashboard:metrics:%s", userID)
}

func QueryCacheKey(query string, params ...interface{}) string {
	return fmt.Sprintf("query:%x", fmt.Sprintf("%s:%v", query, params))
}