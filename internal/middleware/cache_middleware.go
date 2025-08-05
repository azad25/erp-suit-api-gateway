package middleware

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"your-project/internal/cache"
)

// CacheMiddleware provides HTTP response caching
type CacheMiddleware struct {
	cache *cache.CacheManager
}

// NewCacheMiddleware creates a new cache middleware
func NewCacheMiddleware(cacheManager *cache.CacheManager) *CacheMiddleware {
	return &CacheMiddleware{
		cache: cacheManager,
	}
}

// CacheResponse caches GET responses for specified duration
func (cm *CacheMiddleware) CacheResponse(ttl time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only cache GET requests
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}

		// Generate cache key from request
		cacheKey := cm.generateCacheKey(c)

		// Try to get from cache
		var cachedResponse CachedResponse
		if found, err := cm.cache.Get(cacheKey, &cachedResponse); err == nil && found {
			// Set cached headers
			for key, value := range cachedResponse.Headers {
				c.Header(key, value)
			}
			
			// Add cache hit header
			c.Header("X-Cache", "HIT")
			c.Header("X-Cache-Key", cacheKey)
			
			c.Data(cachedResponse.StatusCode, cachedResponse.ContentType, cachedResponse.Body)
			c.Abort()
			return
		}

		// Create response writer wrapper
		writer := &responseWriter{
			ResponseWriter: c.Writer,
			body:          &bytes.Buffer{},
		}
		c.Writer = writer

		// Process request
		c.Next()

		// Cache successful responses
		if writer.status >= 200 && writer.status < 300 {
			response := CachedResponse{
				StatusCode:  writer.status,
				ContentType: writer.Header().Get("Content-Type"),
				Body:        writer.body.Bytes(),
				Headers:     make(map[string]string),
			}

			// Copy important headers
			for _, header := range []string{"Content-Type", "ETag", "Last-Modified"} {
				if value := writer.Header().Get(header); value != "" {
					response.Headers[header] = value
				}
			}

			// Add cache control headers
			response.Headers["Cache-Control"] = fmt.Sprintf("public, max-age=%d", int(ttl.Seconds()))
			response.Headers["X-Cache"] = "MISS"

			// Store in cache
			cm.cache.Set(cacheKey, response, ttl)
		}
	}
}

// ConditionalCache handles ETag and Last-Modified headers
func (cm *CacheMiddleware) ConditionalCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only for GET requests
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}

		cacheKey := cm.generateCacheKey(c)
		
		// Check for conditional headers
		ifNoneMatch := c.GetHeader("If-None-Match")
		ifModifiedSince := c.GetHeader("If-Modified-Since")

		if ifNoneMatch != "" || ifModifiedSince != "" {
			var cachedResponse CachedResponse
			if found, err := cm.cache.Get(cacheKey, &cachedResponse); err == nil && found {
				// Check ETag
				if ifNoneMatch != "" && cachedResponse.Headers["ETag"] == ifNoneMatch {
					c.Status(http.StatusNotModified)
					c.Abort()
					return
				}

				// Check Last-Modified
				if ifModifiedSince != "" {
					if lastModified := cachedResponse.Headers["Last-Modified"]; lastModified != "" {
						if lastModTime, err := time.Parse(time.RFC1123, lastModified); err == nil {
							if ifModTime, err := time.Parse(time.RFC1123, ifModifiedSince); err == nil {
								if !lastModTime.After(ifModTime) {
									c.Status(http.StatusNotModified)
									c.Abort()
									return
								}
							}
						}
					}
				}
			}
		}

		c.Next()
	}
}

// UserSpecificCache caches responses per user
func (cm *CacheMiddleware) UserSpecificCache(ttl time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}

		// Get user ID from context (set by auth middleware)
		userID, exists := c.Get("user_id")
		if !exists {
			c.Next()
			return
		}

		cacheKey := fmt.Sprintf("user:%v:%s", userID, cm.generateCacheKey(c))

		var cachedResponse CachedResponse
		if found, err := cm.cache.Get(cacheKey, &cachedResponse); err == nil && found {
			for key, value := range cachedResponse.Headers {
				c.Header(key, value)
			}
			c.Header("X-Cache", "HIT")
			c.Data(cachedResponse.StatusCode, cachedResponse.ContentType, cachedResponse.Body)
			c.Abort()
			return
		}

		writer := &responseWriter{
			ResponseWriter: c.Writer,
			body:          &bytes.Buffer{},
		}
		c.Writer = writer

		c.Next()

		if writer.status >= 200 && writer.status < 300 {
			response := CachedResponse{
				StatusCode:  writer.status,
				ContentType: writer.Header().Get("Content-Type"),
				Body:        writer.body.Bytes(),
				Headers:     make(map[string]string),
			}

			for _, header := range []string{"Content-Type", "ETag", "Last-Modified"} {
				if value := writer.Header().Get(header); value != "" {
					response.Headers[header] = value
				}
			}

			response.Headers["Cache-Control"] = "private, max-age=" + strconv.Itoa(int(ttl.Seconds()))
			response.Headers["X-Cache"] = "MISS"

			cm.cache.Set(cacheKey, response, ttl)
		}
	}
}

// CachedResponse represents a cached HTTP response
type CachedResponse struct {
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type"`
	Body        []byte            `json:"body"`
	Headers     map[string]string `json:"headers"`
}

// responseWriter wraps gin.ResponseWriter to capture response
type responseWriter struct {
	gin.ResponseWriter
	body   *bytes.Buffer
	status int
}

func (w *responseWriter) Write(data []byte) (int, error) {
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// generateCacheKey creates a unique cache key for the request
func (cm *CacheMiddleware) generateCacheKey(c *gin.Context) string {
	// Include path, query parameters, and relevant headers
	key := fmt.Sprintf("%s:%s", c.Request.Method, c.Request.URL.Path)
	
	if c.Request.URL.RawQuery != "" {
		key += "?" + c.Request.URL.RawQuery
	}

	// Include Accept header for content negotiation
	if accept := c.GetHeader("Accept"); accept != "" {
		key += ":accept:" + accept
	}

	// Create MD5 hash for shorter keys
	hash := md5.Sum([]byte(key))
	return fmt.Sprintf("http:%x", hash)
}

// InvalidateUserCache removes all cached responses for a user
func (cm *CacheMiddleware) InvalidateUserCache(userID string) error {
	pattern := fmt.Sprintf("user:%s:*", userID)
	return cm.cache.DeletePattern(pattern)
}

// InvalidatePathCache removes cached responses for a specific path
func (cm *CacheMiddleware) InvalidatePathCache(path string) error {
	// This is a simplified approach - in production, you'd want more sophisticated cache tagging
	pattern := fmt.Sprintf("http:*%s*", strings.ReplaceAll(path, "/", ""))
	return cm.cache.DeletePattern(pattern)
}