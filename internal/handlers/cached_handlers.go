package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"your-project/internal/cache"
	"your-project/internal/services"
)

// CachedHandlers provides cached API endpoints
type CachedHandlers struct {
	cache           *cache.CacheManager
	userService     *services.UserService
	configService   *services.ConfigService
	warmingService  *services.CacheWarmingService
}

// NewCachedHandlers creates new cached handlers
func NewCachedHandlers(
	cacheManager *cache.CacheManager,
	userService *services.UserService,
	configService *services.ConfigService,
	warmingService *services.CacheWarmingService,
) *CachedHandlers {
	return &CachedHandlers{
		cache:          cacheManager,
		userService:    userService,
		configService:  configService,
		warmingService: warmingService,
	}
}

// GetUserProfile returns cached user profile
func (h *CachedHandlers) GetUserProfile(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Try cache first
	cacheKey := cache.UserCacheKey(userID)
	var user services.User
	
	if found, err := h.cache.Get(cacheKey, &user); err == nil && found {
		// Add cache headers
		c.Header("X-Cache", "HIT")
		c.Header("Cache-Control", "private, max-age=900") // 15 minutes
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    user,
		})
		return
	}

	// Cache miss - fetch from database
	userProfile, err := h.userService.GetUserProfile(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to fetch user profile",
		})
		return
	}

	// Cache the result
	h.cache.Set(cacheKey, userProfile, 15*time.Minute)

	// Add cache headers
	c.Header("X-Cache", "MISS")
	c.Header("Cache-Control", "private, max-age=900")
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    userProfile,
	})
}

// GetUserPermissions returns cached user permissions
func (h *CachedHandlers) GetUserPermissions(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	cacheKey := cache.UserPermissionsCacheKey(userID)
	var permissions []services.Permission

	if found, err := h.cache.Get(cacheKey, &permissions); err == nil && found {
		c.Header("X-Cache", "HIT")
		c.Header("Cache-Control", "private, max-age=1800") // 30 minutes
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    permissions,
		})
		return
	}

	// Fetch from service
	userPermissions, err := h.userService.GetUserPermissions(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to fetch user permissions",
		})
		return
	}

	// Cache for 30 minutes
	h.cache.Set(cacheKey, userPermissions, 30*time.Minute)

	c.Header("X-Cache", "MISS")
	c.Header("Cache-Control", "private, max-age=1800")
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    userPermissions,
	})
}

// GetSystemConfig returns cached system configuration
func (h *CachedHandlers) GetSystemConfig(c *gin.Context) {
	cacheKey := cache.ConfigCacheKey()
	var config services.SystemConfig

	// Check for version-based cache
	version := c.GetHeader("X-Config-Version")
	if version != "" {
		if found, err := h.cache.GetWithVersion(cacheKey, &config, version); err == nil && found {
			c.Header("X-Cache", "HIT")
			c.Header("Cache-Control", "public, max-age=3600") // 1 hour
			c.Header("X-Config-Version", version)
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data":    config,
			})
			return
		}
	}

	// Regular cache check
	if found, err := h.cache.Get(cacheKey, &config); err == nil && found {
		c.Header("X-Cache", "HIT")
		c.Header("Cache-Control", "public, max-age=3600")
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    config,
		})
		return
	}

	// Fetch from service
	systemConfig, err := h.configService.GetSystemConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to fetch system configuration",
		})
		return
	}

	// Cache with version
	configVersion := systemConfig.Version
	h.cache.SetWithVersion(cacheKey, systemConfig, time.Hour, configVersion)

	c.Header("X-Cache", "MISS")
	c.Header("Cache-Control", "public, max-age=3600")
	c.Header("X-Config-Version", configVersion)
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    systemConfig,
	})
}

// GetDashboardMetrics returns cached dashboard metrics
func (h *CachedHandlers) GetDashboardMetrics(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	cacheKey := cache.DashboardMetricsCacheKey(userID.(string))
	var metrics services.DashboardMetrics

	if found, err := h.cache.Get(cacheKey, &metrics); err == nil && found {
		c.Header("X-Cache", "HIT")
		c.Header("Cache-Control", "private, max-age=300") // 5 minutes
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    metrics,
		})
		return
	}

	// Fetch fresh metrics
	dashboardMetrics, err := h.userService.GetDashboardMetrics(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to fetch dashboard metrics",
		})
		return
	}

	// Cache for 5 minutes
	h.cache.Set(cacheKey, dashboardMetrics, 5*time.Minute)

	c.Header("X-Cache", "MISS")
	c.Header("Cache-Control", "private, max-age=300")
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    dashboardMetrics,
	})
}

// InvalidateUserCache clears cache for a specific user
func (h *CachedHandlers) InvalidateUserCache(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Invalidate user-specific cache
	if err := h.warmingService.InvalidateUserData(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to invalidate user cache",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User cache invalidated successfully",
	})
}

// WarmUserCache preloads cache for a specific user
func (h *CachedHandlers) WarmUserCache(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Warm user cache
	if err := h.warmingService.WarmUserData(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to warm user cache",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User cache warmed successfully",
	})
}

// GetCacheStats returns cache statistics
func (h *CachedHandlers) GetCacheStats(c *gin.Context) {
	stats := h.warmingService.GetCacheStats()
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}