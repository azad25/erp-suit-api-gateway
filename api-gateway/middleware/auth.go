package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"erp-api-gateway/internal/interfaces"
)

const (
	// Context keys for storing user information
	UserClaimsKey = "user_claims"
	UserIDKey     = "user_id"
	UserRolesKey  = "user_roles"
	UserPermsKey  = "user_permissions"
)

// AuthMiddleware handles JWT authentication
type AuthMiddleware struct {
	jwtValidator interfaces.JWTValidator
	cache        interfaces.CacheService
}

// NewAuthMiddleware creates a new authentication middleware instance
func NewAuthMiddleware(jwtValidator interfaces.JWTValidator, cache interfaces.CacheService) *AuthMiddleware {
	return &AuthMiddleware{
		jwtValidator: jwtValidator,
		cache:        cache,
	}
}

// ValidateJWT is a middleware that validates JWT tokens from the Authorization header
func (m *AuthMiddleware) ValidateJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.respondWithError(c, http.StatusUnauthorized, "Authorization header is required", nil)
			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.respondWithError(c, http.StatusUnauthorized, "Invalid authorization header format", nil)
			return
		}

		// Extract the token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			m.respondWithError(c, http.StatusUnauthorized, "Token is required", nil)
			return
		}

		// Validate the token
		claims, err := m.jwtValidator.ValidateToken(token)
		if err != nil {
			m.respondWithError(c, http.StatusUnauthorized, "Invalid token", map[string][]string{
				"token": {err.Error()},
			})
			return
		}

		// Store claims in context for use by subsequent handlers
		c.Set(UserClaimsKey, claims)
		c.Set(UserIDKey, claims.UserID)
		c.Set(UserRolesKey, claims.Roles)
		c.Set(UserPermsKey, claims.Permissions)

		// Cache user claims for performance (optional)
		if m.cache != nil {
			go m.cacheUserClaims(claims)
		}

		c.Next()
	}
}

// OptionalJWT is a middleware that validates JWT tokens if present but doesn't require them
func (m *AuthMiddleware) OptionalJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No token provided, continue without authentication
			c.Next()
			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			// Invalid format, continue without authentication
			c.Next()
			return
		}

		// Extract the token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			// Empty token, continue without authentication
			c.Next()
			return
		}

		// Validate the token
		claims, err := m.jwtValidator.ValidateToken(token)
		if err != nil {
			// Invalid token, continue without authentication
			c.Next()
			return
		}

		// Store claims in context for use by subsequent handlers
		c.Set(UserClaimsKey, claims)
		c.Set(UserIDKey, claims.UserID)
		c.Set(UserRolesKey, claims.Roles)
		c.Set(UserPermsKey, claims.Permissions)

		// Cache user claims for performance (optional)
		if m.cache != nil {
			go m.cacheUserClaims(claims)
		}

		c.Next()
	}
}

// ExtractClaims is a middleware that extracts user claims from context
// This should be used after ValidateJWT middleware
func (m *AuthMiddleware) ExtractClaims() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get claims from context (set by ValidateJWT middleware)
		claimsInterface, exists := c.Get(UserClaimsKey)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, "User not authenticated", nil)
			return
		}

		claims, ok := claimsInterface.(*interfaces.Claims)
		if !ok {
			m.respondWithError(c, http.StatusInternalServerError, "Invalid user claims", nil)
			return
		}

		// Verify token is not expired
		if time.Now().Unix() > claims.ExpiresAt {
			m.respondWithError(c, http.StatusUnauthorized, "Token has expired", nil)
			return
		}

		c.Next()
	}
}

// RequireAuth combines JWT validation and claims extraction
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// First validate JWT
		m.ValidateJWT()(c)
		if c.IsAborted() {
			return
		}

		// Then extract claims
		m.ExtractClaims()(c)
		if c.IsAborted() {
			return
		}
	})
}

// cacheUserClaims caches user claims for performance optimization
func (m *AuthMiddleware) cacheUserClaims(claims *interfaces.Claims) {
	if m.cache == nil {
		return
	}

	ctx := context.Background()
	cacheKey := fmt.Sprintf("user:claims:%s", claims.UserID)

	// Serialize claims to JSON
	claimsData, err := json.Marshal(claims)
	if err != nil {
		return
	}

	// Cache until token expires
	ttl := time.Until(time.Unix(claims.ExpiresAt, 0))
	if ttl > 0 {
		m.cache.Set(ctx, cacheKey, claimsData, ttl)
	}
}

// respondWithError sends a standardized error response
func (m *AuthMiddleware) respondWithError(c *gin.Context, statusCode int, message string, errors map[string][]string) {
	response := gin.H{
		"success": false,
		"message": message,
	}

	if errors != nil {
		response["errors"] = errors
	}

	c.JSON(statusCode, response)
	c.Abort()
}

// Helper functions to extract user information from context

// GetUserClaims extracts user claims from the Gin context
func GetUserClaims(c *gin.Context) (*interfaces.Claims, bool) {
	claimsInterface, exists := c.Get(UserClaimsKey)
	if !exists {
		return nil, false
	}

	claims, ok := claimsInterface.(*interfaces.Claims)
	return claims, ok
}

// GetUserID extracts user ID from the Gin context
func GetUserID(c *gin.Context) (string, bool) {
	userIDInterface, exists := c.Get(UserIDKey)
	if !exists {
		return "", false
	}

	userID, ok := userIDInterface.(string)
	return userID, ok
}

// GetUserRoles extracts user roles from the Gin context
func GetUserRoles(c *gin.Context) ([]string, bool) {
	rolesInterface, exists := c.Get(UserRolesKey)
	if !exists {
		return nil, false
	}

	roles, ok := rolesInterface.([]string)
	return roles, ok
}

// GetUserPermissions extracts user permissions from the Gin context
func GetUserPermissions(c *gin.Context) ([]string, bool) {
	permsInterface, exists := c.Get(UserPermsKey)
	if !exists {
		return nil, false
	}

	permissions, ok := permsInterface.([]string)
	return permissions, ok
}

// IsAuthenticated checks if the current request is authenticated
func IsAuthenticated(c *gin.Context) bool {
	_, exists := c.Get(UserClaimsKey)
	return exists
}

// HasRole checks if the current user has a specific role
func HasRole(c *gin.Context, role string) bool {
	roles, exists := GetUserRoles(c)
	if !exists {
		return false
	}

	for _, userRole := range roles {
		if userRole == role {
			return true
		}
	}
	return false
}

// HasPermission checks if the current user has a specific permission
func HasPermission(c *gin.Context, permission string) bool {
	permissions, exists := GetUserPermissions(c)
	if !exists {
		return false
	}

	for _, userPerm := range permissions {
		if userPerm == permission {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the current user has any of the specified roles
func HasAnyRole(c *gin.Context, roles ...string) bool {
	for _, role := range roles {
		if HasRole(c, role) {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the current user has any of the specified permissions
func HasAnyPermission(c *gin.Context, permissions ...string) bool {
	for _, permission := range permissions {
		if HasPermission(c, permission) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the current user has all of the specified roles
func HasAllRoles(c *gin.Context, roles ...string) bool {
	for _, role := range roles {
		if !HasRole(c, role) {
			return false
		}
	}
	return true
}

// HasAllPermissions checks if the current user has all of the specified permissions
func HasAllPermissions(c *gin.Context, permissions ...string) bool {
	for _, permission := range permissions {
		if !HasPermission(c, permission) {
			return false
		}
	}
	return true
}