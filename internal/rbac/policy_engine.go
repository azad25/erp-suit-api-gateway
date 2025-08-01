package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"erp-api-gateway/internal/interfaces"
)

// DefaultPolicyEngine implements the PolicyEngine interface
type DefaultPolicyEngine struct {
	cache     interfaces.CacheService
	hierarchy interfaces.RoleHierarchy
	config    *interfaces.RBACConfig
}

// NewDefaultPolicyEngine creates a new policy engine instance
func NewDefaultPolicyEngine(cache interfaces.CacheService, hierarchy interfaces.RoleHierarchy, config *interfaces.RBACConfig) *DefaultPolicyEngine {
	if config == nil {
		config = &interfaces.RBACConfig{
			EnableHierarchy:   true,
			CacheTTL:         300, // 5 minutes
			DefaultDenyAll:   true,
			SuperAdminRole:   "super_admin",
			GuestRole:        "guest",
			PermissionFormat: "resource:action",
		}
	}

	return &DefaultPolicyEngine{
		cache:     cache,
		hierarchy: hierarchy,
		config:    config,
	}
}

// CheckPermission checks if a user has a specific permission
func (pe *DefaultPolicyEngine) CheckPermission(ctx context.Context, userID string, permission string, claims *interfaces.Claims) (bool, error) {
	// Check for super admin role first
	if pe.config.SuperAdminRole != "" && pe.hasRole(claims.Roles, pe.config.SuperAdminRole) {
		return true, nil
	}

	// Check direct permissions first
	if pe.hasPermission(claims.Permissions, permission) {
		return true, nil
	}

	// If hierarchy is enabled, check inherited permissions
	if pe.config.EnableHierarchy && pe.hierarchy != nil {
		inheritedPerms := pe.hierarchy.GetInheritedPermissions(claims.Roles)
		if pe.hasPermission(inheritedPerms, permission) {
			return true, nil
		}
	}

	// Check cached permissions
	cachedPerms, err := pe.getCachedPermissions(ctx, userID)
	if err == nil && pe.hasPermission(cachedPerms, permission) {
		return true, nil
	}

	return false, nil
}

// CheckRole checks if a user has a specific role
func (pe *DefaultPolicyEngine) CheckRole(ctx context.Context, userID string, role string, claims *interfaces.Claims) (bool, error) {
	// Check direct roles first
	if pe.hasRole(claims.Roles, role) {
		return true, nil
	}

	// If hierarchy is enabled, check inherited roles
	if pe.config.EnableHierarchy && pe.hierarchy != nil {
		if pe.hierarchy.IsRoleInherited(claims.Roles, role) {
			return true, nil
		}
	}

	return false, nil
}

// CheckAnyPermission checks if a user has any of the specified permissions
func (pe *DefaultPolicyEngine) CheckAnyPermission(ctx context.Context, userID string, permissions []string, claims *interfaces.Claims) (bool, error) {
	for _, permission := range permissions {
		hasPermission, err := pe.CheckPermission(ctx, userID, permission, claims)
		if err != nil {
			return false, err
		}
		if hasPermission {
			return true, nil
		}
	}
	return false, nil
}

// CheckAllPermissions checks if a user has all of the specified permissions
func (pe *DefaultPolicyEngine) CheckAllPermissions(ctx context.Context, userID string, permissions []string, claims *interfaces.Claims) (bool, error) {
	for _, permission := range permissions {
		hasPermission, err := pe.CheckPermission(ctx, userID, permission, claims)
		if err != nil {
			return false, err
		}
		if !hasPermission {
			return false, nil
		}
	}
	return true, nil
}

// CheckAnyRole checks if a user has any of the specified roles
func (pe *DefaultPolicyEngine) CheckAnyRole(ctx context.Context, userID string, roles []string, claims *interfaces.Claims) (bool, error) {
	for _, role := range roles {
		hasRole, err := pe.CheckRole(ctx, userID, role, claims)
		if err != nil {
			return false, err
		}
		if hasRole {
			return true, nil
		}
	}
	return false, nil
}

// CheckAllRoles checks if a user has all of the specified roles
func (pe *DefaultPolicyEngine) CheckAllRoles(ctx context.Context, userID string, roles []string, claims *interfaces.Claims) (bool, error) {
	for _, role := range roles {
		hasRole, err := pe.CheckRole(ctx, userID, role, claims)
		if err != nil {
			return false, err
		}
		if !hasRole {
			return false, nil
		}
	}
	return true, nil
}

// GetUserPermissions retrieves all permissions for a user (including inherited)
func (pe *DefaultPolicyEngine) GetUserPermissions(ctx context.Context, userID string, claims *interfaces.Claims) ([]string, error) {
	// Start with direct permissions
	allPermissions := make(map[string]bool)
	for _, perm := range claims.Permissions {
		allPermissions[perm] = true
	}

	// Add inherited permissions if hierarchy is enabled
	if pe.config.EnableHierarchy && pe.hierarchy != nil {
		inheritedPerms := pe.hierarchy.GetInheritedPermissions(claims.Roles)
		for _, perm := range inheritedPerms {
			allPermissions[perm] = true
		}
	}

	// Convert map to slice
	permissions := make([]string, 0, len(allPermissions))
	for perm := range allPermissions {
		permissions = append(permissions, perm)
	}

	// Cache the result
	if pe.cache != nil {
		go pe.cacheUserPermissions(ctx, userID, permissions)
	}

	return permissions, nil
}

// GetUserRoles retrieves all roles for a user (including inherited)
func (pe *DefaultPolicyEngine) GetUserRoles(ctx context.Context, userID string, claims *interfaces.Claims) ([]string, error) {
	// Start with direct roles
	allRoles := make(map[string]bool)
	for _, role := range claims.Roles {
		allRoles[role] = true
	}

	// Add parent roles if hierarchy is enabled
	if pe.config.EnableHierarchy && pe.hierarchy != nil {
		for _, role := range claims.Roles {
			parentRoles := pe.hierarchy.GetParentRoles(role)
			for _, parentRole := range parentRoles {
				allRoles[parentRole] = true
			}
		}
	}

	// Convert map to slice
	roles := make([]string, 0, len(allRoles))
	for role := range allRoles {
		roles = append(roles, role)
	}

	return roles, nil
}

// RefreshUserPermissions refreshes cached permissions for a user
func (pe *DefaultPolicyEngine) RefreshUserPermissions(ctx context.Context, userID string) error {
	if pe.cache == nil {
		return nil
	}

	// Delete cached permissions
	cacheKey := fmt.Sprintf("rbac:permissions:%s", userID)
	return pe.cache.Delete(ctx, cacheKey)
}

// Helper methods

// hasPermission checks if a permission exists in a list of permissions
func (pe *DefaultPolicyEngine) hasPermission(permissions []string, targetPermission string) bool {
	for _, perm := range permissions {
		if perm == targetPermission {
			return true
		}
		// Support wildcard permissions (e.g., "users:*" matches "users:read")
		if strings.HasSuffix(perm, ":*") {
			prefix := strings.TrimSuffix(perm, "*")
			if strings.HasPrefix(targetPermission, prefix) {
				return true
			}
		}
	}
	return false
}

// hasRole checks if a role exists in a list of roles
func (pe *DefaultPolicyEngine) hasRole(roles []string, targetRole string) bool {
	for _, role := range roles {
		if role == targetRole {
			return true
		}
	}
	return false
}

// getCachedPermissions retrieves cached permissions for a user
func (pe *DefaultPolicyEngine) getCachedPermissions(ctx context.Context, userID string) ([]string, error) {
	if pe.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	cacheKey := fmt.Sprintf("rbac:permissions:%s", userID)
	data, err := pe.cache.Get(ctx, cacheKey)
	if err != nil {
		return nil, err
	}

	var permissions []string
	if err := json.Unmarshal(data, &permissions); err != nil {
		return nil, err
	}

	return permissions, nil
}

// cacheUserPermissions caches user permissions
func (pe *DefaultPolicyEngine) cacheUserPermissions(ctx context.Context, userID string, permissions []string) {
	if pe.cache == nil {
		return
	}

	cacheKey := fmt.Sprintf("rbac:permissions:%s", userID)
	data, err := json.Marshal(permissions)
	if err != nil {
		return
	}

	ttl := time.Duration(pe.config.CacheTTL) * time.Second
	pe.cache.Set(ctx, cacheKey, data, ttl)
}