package rbac

import (
	"fmt"
	"sync"

	"erp-api-gateway/internal/interfaces"
)

// DefaultRoleHierarchy implements the RoleHierarchy interface
type DefaultRoleHierarchy struct {
	roles     map[string]*interfaces.Role
	hierarchy map[string][]string // role -> parent roles
	children  map[string][]string // role -> child roles
	mutex     sync.RWMutex
}

// NewDefaultRoleHierarchy creates a new role hierarchy instance
func NewDefaultRoleHierarchy() *DefaultRoleHierarchy {
	rh := &DefaultRoleHierarchy{
		roles:     make(map[string]*interfaces.Role),
		hierarchy: make(map[string][]string),
		children:  make(map[string][]string),
	}

	// Initialize with default role hierarchy
	rh.initializeDefaultHierarchy()

	return rh
}

// initializeDefaultHierarchy sets up a default role hierarchy
func (rh *DefaultRoleHierarchy) initializeDefaultHierarchy() {
	// Define default roles with hierarchy
	defaultRoles := []*interfaces.Role{
		{
			Name:        "super_admin",
			Description: "Super Administrator with all permissions",
			Level:       0,
			Permissions: []interfaces.Permission{
				{Name: "*:*", Description: "All permissions", Resource: "*", Action: "*"},
			},
		},
		{
			Name:        "admin",
			Description: "Administrator with most permissions",
			Level:       1,
			ParentRoles: []string{"super_admin"},
			Permissions: []interfaces.Permission{
				{Name: "users:*", Description: "All user operations", Resource: "users", Action: "*"},
				{Name: "roles:*", Description: "All role operations", Resource: "roles", Action: "*"},
				{Name: "system:read", Description: "System read access", Resource: "system", Action: "read"},
			},
		},
		{
			Name:        "manager",
			Description: "Manager with team management permissions",
			Level:       2,
			ParentRoles: []string{"admin"},
			Permissions: []interfaces.Permission{
				{Name: "team:*", Description: "All team operations", Resource: "team", Action: "*"},
				{Name: "projects:*", Description: "All project operations", Resource: "projects", Action: "*"},
				{Name: "reports:read", Description: "Report read access", Resource: "reports", Action: "read"},
			},
		},
		{
			Name:        "user",
			Description: "Regular user with basic permissions",
			Level:       3,
			ParentRoles: []string{"manager"},
			Permissions: []interfaces.Permission{
				{Name: "profile:read", Description: "Profile read access", Resource: "profile", Action: "read"},
				{Name: "profile:update", Description: "Profile update access", Resource: "profile", Action: "update"},
				{Name: "dashboard:read", Description: "Dashboard read access", Resource: "dashboard", Action: "read"},
			},
		},
		{
			Name:        "guest",
			Description: "Guest user with minimal permissions",
			Level:       4,
			Permissions: []interfaces.Permission{
				{Name: "public:read", Description: "Public content read access", Resource: "public", Action: "read"},
			},
		},
	}

	// Add roles to the hierarchy
	for _, role := range defaultRoles {
		rh.AddRole(role)
	}
}

// AddRole adds a role to the hierarchy
func (rh *DefaultRoleHierarchy) AddRole(role *interfaces.Role) {
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	rh.roles[role.Name] = role

	// Update hierarchy mappings
	if len(role.ParentRoles) > 0 {
		rh.hierarchy[role.Name] = role.ParentRoles
		
		// Update children mappings
		for _, parentRole := range role.ParentRoles {
			if rh.children[parentRole] == nil {
				rh.children[parentRole] = make([]string, 0)
			}
			rh.children[parentRole] = append(rh.children[parentRole], role.Name)
		}
	}
}

// GetParentRoles returns the parent roles for a given role
func (rh *DefaultRoleHierarchy) GetParentRoles(role string) []string {
	rh.mutex.RLock()
	defer rh.mutex.RUnlock()

	_, exists := rh.hierarchy[role]
	if !exists {
		return []string{}
	}

	// Get all parent roles recursively
	allParents := make(map[string]bool)
	rh.collectParentRoles(role, allParents)

	result := make([]string, 0, len(allParents))
	for parent := range allParents {
		result = append(result, parent)
	}

	return result
}

// GetChildRoles returns the child roles for a given role
func (rh *DefaultRoleHierarchy) GetChildRoles(role string) []string {
	rh.mutex.RLock()
	defer rh.mutex.RUnlock()

	_, exists := rh.children[role]
	if !exists {
		return []string{}
	}

	// Get all child roles recursively
	allChildren := make(map[string]bool)
	rh.collectChildRoles(role, allChildren)

	result := make([]string, 0, len(allChildren))
	for child := range allChildren {
		result = append(result, child)
	}

	return result
}

// IsRoleInherited checks if a role is inherited from parent roles
func (rh *DefaultRoleHierarchy) IsRoleInherited(userRoles []string, targetRole string) bool {
	rh.mutex.RLock()
	defer rh.mutex.RUnlock()

	// Check if user has the role directly
	for _, userRole := range userRoles {
		if userRole == targetRole {
			return true
		}
	}

	// Check if any user role inherits the target role
	for _, userRole := range userRoles {
		if rh.roleInheritsRole(userRole, targetRole) {
			return true
		}
	}

	return false
}

// GetInheritedPermissions returns permissions inherited from role hierarchy
func (rh *DefaultRoleHierarchy) GetInheritedPermissions(roles []string) []string {
	rh.mutex.RLock()
	defer rh.mutex.RUnlock()

	allPermissions := make(map[string]bool)

	// Collect permissions from all roles and their parents
	for _, role := range roles {
		rh.collectRolePermissions(role, allPermissions)
	}

	result := make([]string, 0, len(allPermissions))
	for permission := range allPermissions {
		result = append(result, permission)
	}

	return result
}

// GetRole returns a role by name
func (rh *DefaultRoleHierarchy) GetRole(roleName string) (*interfaces.Role, bool) {
	rh.mutex.RLock()
	defer rh.mutex.RUnlock()

	role, exists := rh.roles[roleName]
	return role, exists
}

// GetAllRoles returns all roles in the hierarchy
func (rh *DefaultRoleHierarchy) GetAllRoles() map[string]*interfaces.Role {
	rh.mutex.RLock()
	defer rh.mutex.RUnlock()

	result := make(map[string]*interfaces.Role)
	for name, role := range rh.roles {
		result[name] = role
	}

	return result
}

// Helper methods

// collectParentRoles recursively collects all parent roles
func (rh *DefaultRoleHierarchy) collectParentRoles(role string, visited map[string]bool) {
	parents, exists := rh.hierarchy[role]
	if !exists {
		return
	}

	for _, parent := range parents {
		if !visited[parent] {
			visited[parent] = true
			rh.collectParentRoles(parent, visited)
		}
	}
}

// collectChildRoles recursively collects all child roles
func (rh *DefaultRoleHierarchy) collectChildRoles(role string, visited map[string]bool) {
	children, exists := rh.children[role]
	if !exists {
		return
	}

	for _, child := range children {
		if !visited[child] {
			visited[child] = true
			rh.collectChildRoles(child, visited)
		}
	}
}

// roleInheritsRole checks if a role inherits another role through hierarchy
func (rh *DefaultRoleHierarchy) roleInheritsRole(userRole, targetRole string) bool {
	// Get all parent roles of the user role
	allParents := make(map[string]bool)
	rh.collectParentRoles(userRole, allParents)

	return allParents[targetRole]
}

// collectRolePermissions recursively collects permissions from a role and its parents
func (rh *DefaultRoleHierarchy) collectRolePermissions(roleName string, permissions map[string]bool) {
	role, exists := rh.roles[roleName]
	if !exists {
		return
	}

	// Add direct permissions
	for _, permission := range role.Permissions {
		permissions[permission.Name] = true
	}

	// Add permissions from parent roles
	parents, exists := rh.hierarchy[roleName]
	if exists {
		for _, parent := range parents {
			rh.collectRolePermissions(parent, permissions)
		}
	}
}

// ValidateHierarchy validates the role hierarchy for cycles and consistency
func (rh *DefaultRoleHierarchy) ValidateHierarchy() error {
	rh.mutex.RLock()
	defer rh.mutex.RUnlock()

	// Check for cycles in the hierarchy
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	for roleName := range rh.roles {
		if !visited[roleName] {
			if rh.hasCycle(roleName, visited, recursionStack) {
				return fmt.Errorf("cycle detected in role hierarchy involving role: %s", roleName)
			}
		}
	}

	return nil
}

// hasCycle checks for cycles in the role hierarchy using DFS
func (rh *DefaultRoleHierarchy) hasCycle(role string, visited, recursionStack map[string]bool) bool {
	visited[role] = true
	recursionStack[role] = true

	parents, exists := rh.hierarchy[role]
	if exists {
		for _, parent := range parents {
			if !visited[parent] {
				if rh.hasCycle(parent, visited, recursionStack) {
					return true
				}
			} else if recursionStack[parent] {
				return true
			}
		}
	}

	recursionStack[role] = false
	return false
}