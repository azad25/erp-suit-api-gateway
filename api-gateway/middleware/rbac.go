package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"erp-api-gateway/internal/interfaces"
)

// RBACMiddleware handles role-based access control
type RBACMiddleware struct {
	policyEngine interfaces.PolicyEngine
	config       *interfaces.RBACConfig
}

// NewRBACMiddleware creates a new RBAC middleware instance
func NewRBACMiddleware(policyEngine interfaces.PolicyEngine, config *interfaces.RBACConfig) *RBACMiddleware {
	if config == nil {
		config = &interfaces.RBACConfig{
			EnableHierarchy:   true,
			CacheTTL:         300,
			DefaultDenyAll:   true,
			SuperAdminRole:   "super_admin",
			GuestRole:        "guest",
			PermissionFormat: "resource:action",
		}
	}

	return &RBACMiddleware{
		policyEngine: policyEngine,
		config:       config,
	}
}

// RequirePermission creates middleware that requires a specific permission
func (m *RBACMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user claims from context (set by auth middleware)
		claims, exists := GetUserClaims(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user has the required permission
		hasPermission, err := m.policyEngine.CheckPermission(c.Request.Context(), claims.UserID, permission, claims)
		if err != nil {
			m.respondWithError(c, http.StatusInternalServerError, "Permission check failed", map[string][]string{
				"permission": {err.Error()},
			})
			return
		}

		if !hasPermission {
			m.respondWithError(c, http.StatusForbidden, "Insufficient permissions", map[string][]string{
				"permission": {permission},
			})
			return
		}

		c.Next()
	}
}

// RequireRole creates middleware that requires a specific role
func (m *RBACMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user claims from context (set by auth middleware)
		claims, exists := GetUserClaims(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user has the required role
		hasRole, err := m.policyEngine.CheckRole(c.Request.Context(), claims.UserID, role, claims)
		if err != nil {
			m.respondWithError(c, http.StatusInternalServerError, "Role check failed", map[string][]string{
				"role": {err.Error()},
			})
			return
		}

		if !hasRole {
			m.respondWithError(c, http.StatusForbidden, "Insufficient role", map[string][]string{
				"role": {role},
			})
			return
		}

		c.Next()
	}
}

// RequireAnyPermission creates middleware that requires any of the specified permissions
func (m *RBACMiddleware) RequireAnyPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user claims from context (set by auth middleware)
		claims, exists := GetUserClaims(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user has any of the required permissions
		hasAnyPermission, err := m.policyEngine.CheckAnyPermission(c.Request.Context(), claims.UserID, permissions, claims)
		if err != nil {
			m.respondWithError(c, http.StatusInternalServerError, "Permission check failed", map[string][]string{
				"permissions": {err.Error()},
			})
			return
		}

		if !hasAnyPermission {
			m.respondWithError(c, http.StatusForbidden, "Insufficient permissions", map[string][]string{
				"permissions": permissions,
			})
			return
		}

		c.Next()
	}
}

// RequireAllPermissions creates middleware that requires all of the specified permissions
func (m *RBACMiddleware) RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user claims from context (set by auth middleware)
		claims, exists := GetUserClaims(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user has all of the required permissions
		hasAllPermissions, err := m.policyEngine.CheckAllPermissions(c.Request.Context(), claims.UserID, permissions, claims)
		if err != nil {
			m.respondWithError(c, http.StatusInternalServerError, "Permission check failed", map[string][]string{
				"permissions": {err.Error()},
			})
			return
		}

		if !hasAllPermissions {
			m.respondWithError(c, http.StatusForbidden, "Insufficient permissions", map[string][]string{
				"permissions": permissions,
			})
			return
		}

		c.Next()
	}
}

// RequireAnyRole creates middleware that requires any of the specified roles
func (m *RBACMiddleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user claims from context (set by auth middleware)
		claims, exists := GetUserClaims(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user has any of the required roles
		hasAnyRole, err := m.policyEngine.CheckAnyRole(c.Request.Context(), claims.UserID, roles, claims)
		if err != nil {
			m.respondWithError(c, http.StatusInternalServerError, "Role check failed", map[string][]string{
				"roles": {err.Error()},
			})
			return
		}

		if !hasAnyRole {
			m.respondWithError(c, http.StatusForbidden, "Insufficient role", map[string][]string{
				"roles": roles,
			})
			return
		}

		c.Next()
	}
}

// RequireAllRoles creates middleware that requires all of the specified roles
func (m *RBACMiddleware) RequireAllRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user claims from context (set by auth middleware)
		claims, exists := GetUserClaims(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user has all of the required roles
		hasAllRoles, err := m.policyEngine.CheckAllRoles(c.Request.Context(), claims.UserID, roles, claims)
		if err != nil {
			m.respondWithError(c, http.StatusInternalServerError, "Role check failed", map[string][]string{
				"roles": {err.Error()},
			})
			return
		}

		if !hasAllRoles {
			m.respondWithError(c, http.StatusForbidden, "Insufficient roles", map[string][]string{
				"roles": roles,
			})
			return
		}

		c.Next()
	}
}

// RequireResourcePermission creates middleware that requires permission for a specific resource and action
func (m *RBACMiddleware) RequireResourcePermission(resource, action string) gin.HandlerFunc {
	permission := formatPermission(resource, action, m.config.PermissionFormat)
	return m.RequirePermission(permission)
}

// RequireSuperAdmin creates middleware that requires super admin role
func (m *RBACMiddleware) RequireSuperAdmin() gin.HandlerFunc {
	return m.RequireRole(m.config.SuperAdminRole)
}

// AllowGuest creates middleware that allows guest access (no authentication required)
func (m *RBACMiddleware) AllowGuest() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Always allow guest access
		c.Next()
	}
}

// ConditionalPermission creates middleware that conditionally checks permissions based on a condition function
func (m *RBACMiddleware) ConditionalPermission(permission string, condition func(*gin.Context) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check condition first
		if !condition(c) {
			c.Next()
			return
		}

		// Apply permission check
		m.RequirePermission(permission)(c)
	}
}

// respondWithError sends a standardized error response
func (m *RBACMiddleware) respondWithError(c *gin.Context, statusCode int, message string, errors map[string][]string) {
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

// Helper functions for common permission checks

// CheckUserPermission checks if the current user has a specific permission
func CheckUserPermission(c *gin.Context, policyEngine interfaces.PolicyEngine, permission string) bool {
	claims, exists := GetUserClaims(c)
	if !exists {
		return false
	}

	hasPermission, err := policyEngine.CheckPermission(c.Request.Context(), claims.UserID, permission, claims)
	if err != nil {
		return false
	}

	return hasPermission
}

// CheckUserRole checks if the current user has a specific role
func CheckUserRole(c *gin.Context, policyEngine interfaces.PolicyEngine, role string) bool {
	claims, exists := GetUserClaims(c)
	if !exists {
		return false
	}

	hasRole, err := policyEngine.CheckRole(c.Request.Context(), claims.UserID, role, claims)
	if err != nil {
		return false
	}

	return hasRole
}

// CheckUserAnyPermission checks if the current user has any of the specified permissions
func CheckUserAnyPermission(c *gin.Context, policyEngine interfaces.PolicyEngine, permissions ...string) bool {
	claims, exists := GetUserClaims(c)
	if !exists {
		return false
	}

	hasAnyPermission, err := policyEngine.CheckAnyPermission(c.Request.Context(), claims.UserID, permissions, claims)
	if err != nil {
		return false
	}

	return hasAnyPermission
}

// CheckUserAllPermissions checks if the current user has all of the specified permissions
func CheckUserAllPermissions(c *gin.Context, policyEngine interfaces.PolicyEngine, permissions ...string) bool {
	claims, exists := GetUserClaims(c)
	if !exists {
		return false
	}

	hasAllPermissions, err := policyEngine.CheckAllPermissions(c.Request.Context(), claims.UserID, permissions, claims)
	if err != nil {
		return false
	}

	return hasAllPermissions
}

// CheckUserAnyRole checks if the current user has any of the specified roles
func CheckUserAnyRole(c *gin.Context, policyEngine interfaces.PolicyEngine, roles ...string) bool {
	claims, exists := GetUserClaims(c)
	if !exists {
		return false
	}

	hasAnyRole, err := policyEngine.CheckAnyRole(c.Request.Context(), claims.UserID, roles, claims)
	if err != nil {
		return false
	}

	return hasAnyRole
}

// CheckUserAllRoles checks if the current user has all of the specified roles
func CheckUserAllRoles(c *gin.Context, policyEngine interfaces.PolicyEngine, roles ...string) bool {
	claims, exists := GetUserClaims(c)
	if !exists {
		return false
	}

	hasAllRoles, err := policyEngine.CheckAllRoles(c.Request.Context(), claims.UserID, roles, claims)
	if err != nil {
		return false
	}

	return hasAllRoles
}

// IsOwnerOrHasPermission checks if the user is the owner of a resource or has a specific permission
func IsOwnerOrHasPermission(c *gin.Context, policyEngine interfaces.PolicyEngine, resourceOwnerID, permission string) bool {
	claims, exists := GetUserClaims(c)
	if !exists {
		return false
	}

	// Check if user is the owner
	if claims.UserID == resourceOwnerID {
		return true
	}

	// Check if user has the required permission
	return CheckUserPermission(c, policyEngine, permission)
}

// formatPermission formats a permission string based on the configured format
func formatPermission(resource, action, format string) string {
	switch format {
	case "resource:action":
		return resource + ":" + action
	case "resource.action":
		return resource + "." + action
	case "action_resource":
		return action + "_" + resource
	default:
		return resource + ":" + action
	}
}

// ParsePermission parses a permission string into resource and action
func ParsePermission(permission, format string) (resource, action string) {
	switch format {
	case "resource:action":
		parts := strings.SplitN(permission, ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	case "resource.action":
		parts := strings.SplitN(permission, ".", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	case "action_resource":
		parts := strings.SplitN(permission, "_", 2)
		if len(parts) == 2 {
			return parts[1], parts[0]
		}
	default:
		parts := strings.SplitN(permission, ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return permission, ""
}