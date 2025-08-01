package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"erp-api-gateway/internal/interfaces"
)

func TestNewDefaultRoleHierarchy(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	// Check that default roles are initialized
	assert.NotNil(t, rh)
	assert.NotEmpty(t, rh.roles)
	assert.NotEmpty(t, rh.hierarchy)
	assert.NotEmpty(t, rh.children)

	// Check specific default roles
	superAdmin, exists := rh.GetRole("super_admin")
	assert.True(t, exists)
	assert.Equal(t, "super_admin", superAdmin.Name)
	assert.Equal(t, 0, superAdmin.Level)

	admin, exists := rh.GetRole("admin")
	assert.True(t, exists)
	assert.Equal(t, "admin", admin.Name)
	assert.Equal(t, 1, admin.Level)
	assert.Contains(t, admin.ParentRoles, "super_admin")

	user, exists := rh.GetRole("user")
	assert.True(t, exists)
	assert.Equal(t, "user", user.Name)
	assert.Equal(t, 3, user.Level)
	assert.Contains(t, user.ParentRoles, "manager")
}

func TestDefaultRoleHierarchy_AddRole(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	// Add a new role
	newRole := &interfaces.Role{
		Name:        "developer",
		Description: "Developer role",
		Level:       2,
		ParentRoles: []string{"admin"},
		Permissions: []interfaces.Permission{
			{Name: "code:write", Description: "Code write access", Resource: "code", Action: "write"},
		},
	}

	rh.AddRole(newRole)

	// Check that the role was added
	role, exists := rh.GetRole("developer")
	assert.True(t, exists)
	assert.Equal(t, "developer", role.Name)
	assert.Equal(t, 2, role.Level)

	// Check hierarchy mappings
	parents := rh.GetParentRoles("developer")
	assert.Contains(t, parents, "admin")

	children := rh.GetChildRoles("admin")
	assert.Contains(t, children, "developer")
}

func TestDefaultRoleHierarchy_GetParentRoles(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	tests := []struct {
		name           string
		role           string
		expectedParents []string
	}{
		{
			name:           "User role parents",
			role:           "user",
			expectedParents: []string{"manager", "admin", "super_admin"},
		},
		{
			name:           "Manager role parents",
			role:           "manager",
			expectedParents: []string{"admin", "super_admin"},
		},
		{
			name:           "Admin role parents",
			role:           "admin",
			expectedParents: []string{"super_admin"},
		},
		{
			name:           "Super admin has no parents",
			role:           "super_admin",
			expectedParents: []string{},
		},
		{
			name:           "Non-existent role",
			role:           "non_existent",
			expectedParents: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parents := rh.GetParentRoles(tt.role)
			
			if len(tt.expectedParents) == 0 {
				assert.Empty(t, parents)
			} else {
				for _, expectedParent := range tt.expectedParents {
					assert.Contains(t, parents, expectedParent)
				}
			}
		})
	}
}

func TestDefaultRoleHierarchy_GetChildRoles(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	tests := []struct {
		name            string
		role            string
		expectedChildren []string
	}{
		{
			name:            "Super admin children",
			role:            "super_admin",
			expectedChildren: []string{"admin", "manager", "user"},
		},
		{
			name:            "Admin children",
			role:            "admin",
			expectedChildren: []string{"manager", "user"},
		},
		{
			name:            "Manager children",
			role:            "manager",
			expectedChildren: []string{"user"},
		},
		{
			name:            "User has no children",
			role:            "user",
			expectedChildren: []string{},
		},
		{
			name:            "Guest has no children",
			role:            "guest",
			expectedChildren: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			children := rh.GetChildRoles(tt.role)
			
			if len(tt.expectedChildren) == 0 {
				assert.Empty(t, children)
			} else {
				for _, expectedChild := range tt.expectedChildren {
					assert.Contains(t, children, expectedChild)
				}
			}
		})
	}
}

func TestDefaultRoleHierarchy_IsRoleInherited(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	tests := []struct {
		name       string
		userRoles  []string
		targetRole string
		expected   bool
	}{
		{
			name:       "Direct role match",
			userRoles:  []string{"manager"},
			targetRole: "manager",
			expected:   true,
		},
		{
			name:       "Inherited role - user inherits manager",
			userRoles:  []string{"user"},
			targetRole: "manager",
			expected:   true,
		},
		{
			name:       "Inherited role - user inherits admin",
			userRoles:  []string{"user"},
			targetRole: "admin",
			expected:   true,
		},
		{
			name:       "Inherited role - user inherits super_admin",
			userRoles:  []string{"user"},
			targetRole: "super_admin",
			expected:   true,
		},
		{
			name:       "Not inherited - admin does not inherit user",
			userRoles:  []string{"admin"},
			targetRole: "user",
			expected:   false,
		},
		{
			name:       "Multiple roles - one inherits target",
			userRoles:  []string{"guest", "manager"},
			targetRole: "admin",
			expected:   true,
		},
		{
			name:       "No inheritance",
			userRoles:  []string{"guest"},
			targetRole: "admin",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rh.IsRoleInherited(tt.userRoles, tt.targetRole)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultRoleHierarchy_GetInheritedPermissions(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	tests := []struct {
		name                 string
		roles                []string
		expectedPermissions  []string
		unexpectedPermissions []string
	}{
		{
			name:  "User role permissions",
			roles: []string{"user"},
			expectedPermissions: []string{
				"profile:read", "profile:update", "dashboard:read", // direct user permissions
				"team:*", "projects:*", "reports:read", // from manager
				"users:*", "roles:*", "system:read", // from admin
				"*:*", // from super_admin
			},
		},
		{
			name:  "Manager role permissions",
			roles: []string{"manager"},
			expectedPermissions: []string{
				"team:*", "projects:*", "reports:read", // direct manager permissions
				"users:*", "roles:*", "system:read", // from admin
				"*:*", // from super_admin
			},
			unexpectedPermissions: []string{
				"profile:read", "profile:update", "dashboard:read", // user-specific permissions
			},
		},
		{
			name:  "Guest role permissions",
			roles: []string{"guest"},
			expectedPermissions: []string{
				"public:read", // direct guest permissions
			},
			unexpectedPermissions: []string{
				"users:*", "team:*", "*:*", // higher-level permissions
			},
		},
		{
			name:  "Multiple roles",
			roles: []string{"guest", "user"},
			expectedPermissions: []string{
				"public:read", // from guest
				"profile:read", "profile:update", "dashboard:read", // from user
				"*:*", // from super_admin (inherited by user)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permissions := rh.GetInheritedPermissions(tt.roles)
			
			for _, expectedPerm := range tt.expectedPermissions {
				assert.Contains(t, permissions, expectedPerm, "Expected permission %s not found", expectedPerm)
			}
			
			for _, unexpectedPerm := range tt.unexpectedPermissions {
				assert.NotContains(t, permissions, unexpectedPerm, "Unexpected permission %s found", unexpectedPerm)
			}
		})
	}
}

func TestDefaultRoleHierarchy_GetRole(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	t.Run("Existing role", func(t *testing.T) {
		role, exists := rh.GetRole("admin")
		assert.True(t, exists)
		assert.Equal(t, "admin", role.Name)
		assert.Equal(t, "Administrator with most permissions", role.Description)
		assert.Equal(t, 1, role.Level)
	})

	t.Run("Non-existing role", func(t *testing.T) {
		role, exists := rh.GetRole("non_existent")
		assert.False(t, exists)
		assert.Nil(t, role)
	})
}

func TestDefaultRoleHierarchy_GetAllRoles(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	allRoles := rh.GetAllRoles()
	
	// Check that all default roles are present
	expectedRoles := []string{"super_admin", "admin", "manager", "user", "guest"}
	assert.Len(t, allRoles, len(expectedRoles))
	
	for _, expectedRole := range expectedRoles {
		role, exists := allRoles[expectedRole]
		assert.True(t, exists, "Role %s should exist", expectedRole)
		assert.Equal(t, expectedRole, role.Name)
	}
}

func TestDefaultRoleHierarchy_ValidateHierarchy(t *testing.T) {
	t.Run("Valid hierarchy", func(t *testing.T) {
		rh := NewDefaultRoleHierarchy()
		err := rh.ValidateHierarchy()
		assert.NoError(t, err)
	})

	t.Run("Hierarchy with cycle", func(t *testing.T) {
		rh := NewDefaultRoleHierarchy()
		
		// Create a cycle: role1 -> role2 -> role3 -> role1
		role1 := &interfaces.Role{
			Name:        "role1",
			ParentRoles: []string{"role3"},
		}
		role2 := &interfaces.Role{
			Name:        "role2",
			ParentRoles: []string{"role1"},
		}
		role3 := &interfaces.Role{
			Name:        "role3",
			ParentRoles: []string{"role2"},
		}

		rh.AddRole(role1)
		rh.AddRole(role2)
		rh.AddRole(role3)

		err := rh.ValidateHierarchy()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cycle detected")
	})
}

func TestDefaultRoleHierarchy_collectParentRoles(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	visited := make(map[string]bool)
	rh.collectParentRoles("user", visited)

	expectedParents := []string{"manager", "admin", "super_admin"}
	for _, parent := range expectedParents {
		assert.True(t, visited[parent], "Parent role %s should be visited", parent)
	}
}

func TestDefaultRoleHierarchy_collectChildRoles(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	visited := make(map[string]bool)
	rh.collectChildRoles("super_admin", visited)

	expectedChildren := []string{"admin", "manager", "user"}
	for _, child := range expectedChildren {
		assert.True(t, visited[child], "Child role %s should be visited", child)
	}
}

func TestDefaultRoleHierarchy_roleInheritsRole(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	tests := []struct {
		name       string
		userRole   string
		targetRole string
		expected   bool
	}{
		{
			name:       "User inherits manager",
			userRole:   "user",
			targetRole: "manager",
			expected:   true,
		},
		{
			name:       "User inherits admin",
			userRole:   "user",
			targetRole: "admin",
			expected:   true,
		},
		{
			name:       "User inherits super_admin",
			userRole:   "user",
			targetRole: "super_admin",
			expected:   true,
		},
		{
			name:       "Admin does not inherit user",
			userRole:   "admin",
			targetRole: "user",
			expected:   false,
		},
		{
			name:       "Manager does not inherit user",
			userRole:   "manager",
			targetRole: "user",
			expected:   false,
		},
		{
			name:       "Guest does not inherit anything",
			userRole:   "guest",
			targetRole: "user",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rh.roleInheritsRole(tt.userRole, tt.targetRole)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultRoleHierarchy_collectRolePermissions(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	permissions := make(map[string]bool)
	rh.collectRolePermissions("user", permissions)

	// Should include permissions from user, manager, admin, and super_admin
	expectedPermissions := []string{
		"profile:read", "profile:update", "dashboard:read", // user
		"team:*", "projects:*", "reports:read", // manager
		"users:*", "roles:*", "system:read", // admin
		"*:*", // super_admin
	}

	for _, perm := range expectedPermissions {
		assert.True(t, permissions[perm], "Permission %s should be collected", perm)
	}
}

func TestDefaultRoleHierarchy_hasCycle(t *testing.T) {
	rh := NewDefaultRoleHierarchy()

	t.Run("No cycle in default hierarchy", func(t *testing.T) {
		visited := make(map[string]bool)
		recursionStack := make(map[string]bool)
		
		hasCycle := rh.hasCycle("user", visited, recursionStack)
		assert.False(t, hasCycle)
	})

	t.Run("Detect cycle", func(t *testing.T) {
		// Create a simple cycle for testing
		testRh := &DefaultRoleHierarchy{
			roles:     make(map[string]*interfaces.Role),
			hierarchy: make(map[string][]string),
			children:  make(map[string][]string),
		}

		// Add roles with cycle: a -> b -> a
		testRh.hierarchy["a"] = []string{"b"}
		testRh.hierarchy["b"] = []string{"a"}
		testRh.roles["a"] = &interfaces.Role{Name: "a"}
		testRh.roles["b"] = &interfaces.Role{Name: "b"}

		visited := make(map[string]bool)
		recursionStack := make(map[string]bool)
		
		hasCycle := testRh.hasCycle("a", visited, recursionStack)
		assert.True(t, hasCycle)
	})
}