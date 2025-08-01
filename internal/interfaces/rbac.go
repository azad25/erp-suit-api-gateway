package interfaces

import (
	"context"
)

// PolicyEngine defines the interface for RBAC policy evaluation
type PolicyEngine interface {
	// CheckPermission checks if a user has a specific permission
	CheckPermission(ctx context.Context, userID string, permission string, claims *Claims) (bool, error)
	
	// CheckRole checks if a user has a specific role
	CheckRole(ctx context.Context, userID string, role string, claims *Claims) (bool, error)
	
	// CheckAnyPermission checks if a user has any of the specified permissions
	CheckAnyPermission(ctx context.Context, userID string, permissions []string, claims *Claims) (bool, error)
	
	// CheckAllPermissions checks if a user has all of the specified permissions
	CheckAllPermissions(ctx context.Context, userID string, permissions []string, claims *Claims) (bool, error)
	
	// CheckAnyRole checks if a user has any of the specified roles
	CheckAnyRole(ctx context.Context, userID string, roles []string, claims *Claims) (bool, error)
	
	// CheckAllRoles checks if a user has all of the specified roles
	CheckAllRoles(ctx context.Context, userID string, roles []string, claims *Claims) (bool, error)
	
	// GetUserPermissions retrieves all permissions for a user (including inherited)
	GetUserPermissions(ctx context.Context, userID string, claims *Claims) ([]string, error)
	
	// GetUserRoles retrieves all roles for a user (including inherited)
	GetUserRoles(ctx context.Context, userID string, claims *Claims) ([]string, error)
	
	// RefreshUserPermissions refreshes cached permissions for a user
	RefreshUserPermissions(ctx context.Context, userID string) error
}

// RoleHierarchy defines the interface for role hierarchy management
type RoleHierarchy interface {
	// GetParentRoles returns the parent roles for a given role
	GetParentRoles(role string) []string
	
	// GetChildRoles returns the child roles for a given role
	GetChildRoles(role string) []string
	
	// IsRoleInherited checks if a role is inherited from parent roles
	IsRoleInherited(userRoles []string, targetRole string) bool
	
	// GetInheritedPermissions returns permissions inherited from role hierarchy
	GetInheritedPermissions(roles []string) []string
}

// Permission represents a permission with its metadata
type Permission struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Conditions  map[string]string `json:"conditions,omitempty"`
}

// Role represents a role with its permissions and hierarchy
type Role struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Permissions  []Permission `json:"permissions"`
	ParentRoles  []string     `json:"parent_roles,omitempty"`
	ChildRoles   []string     `json:"child_roles,omitempty"`
	Level        int          `json:"level"` // For hierarchy ordering
}

// PolicyResult represents the result of a policy evaluation
type PolicyResult struct {
	Allowed     bool              `json:"allowed"`
	Reason      string            `json:"reason"`
	Permission  string            `json:"permission,omitempty"`
	Role        string            `json:"role,omitempty"`
	Context     map[string]string `json:"context,omitempty"`
}

// RBACConfig represents RBAC configuration
type RBACConfig struct {
	EnableHierarchy     bool          `json:"enable_hierarchy"`
	CacheTTL           int           `json:"cache_ttl_seconds"`
	DefaultDenyAll     bool          `json:"default_deny_all"`
	SuperAdminRole     string        `json:"super_admin_role"`
	GuestRole          string        `json:"guest_role"`
	PermissionFormat   string        `json:"permission_format"` // e.g., "resource:action"
}