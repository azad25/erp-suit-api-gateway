package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// RedisCache implements the CacheService interface using Redis
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(cfg *config.RedisConfig) *RedisCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	return &RedisCache{
		client: rdb,
	}
}

// Get retrieves a value from the cache
func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, interfaces.ErrCacheKeyNotFound
		}
		return nil, err
	}
	return []byte(val), nil
}

// Set stores a value in the cache with TTL
func (r *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

// Delete removes a key from the cache
func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// Exists checks if a key exists in the cache
func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	count, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// SetNX sets a key only if it doesn't exist
func (r *RedisCache) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, ttl).Result()
}

// Increment increments a key's value
func (r *RedisCache) Increment(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// Expire sets a TTL on an existing key
func (r *RedisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return r.client.Expire(ctx, key, ttl).Err()
}

// Close closes the Redis connection
func (r *RedisCache) Close() error {
	return r.client.Close()
}

// Ping tests the Redis connection
func (r *RedisCache) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

