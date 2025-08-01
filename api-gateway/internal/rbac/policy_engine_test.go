package rbac

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"erp-api-gateway/internal/interfaces"
)

// MockCacheService is a mock implementation of CacheService
type MockCacheService struct {
	mock.Mock
}

func (m *MockCacheService) Get(ctx context.Context, key string) ([]byte, error) {
	args := m.Called(ctx, key)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCacheService) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	args := m.Called(ctx, key, value, ttl)
	return args.Error(0)
}

func (m *MockCacheService) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockCacheService) Exists(ctx context.Context, key string) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

func (m *MockCacheService) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	args := m.Called(ctx, key, value, ttl)
	return args.Bool(0), args.Error(1)
}

func (m *MockCacheService) Increment(ctx context.Context, key string) (int64, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockCacheService) Expire(ctx context.Context, key string, ttl time.Duration) error {
	args := m.Called(ctx, key, ttl)
	return args.Error(0)
}

// MockRoleHierarchy is a mock implementation of RoleHierarchy
type MockRoleHierarchy struct {
	mock.Mock
}

func (m *MockRoleHierarchy) GetParentRoles(role string) []string {
	args := m.Called(role)
	return args.Get(0).([]string)
}

func (m *MockRoleHierarchy) GetChildRoles(role string) []string {
	args := m.Called(role)
	return args.Get(0).([]string)
}

func (m *MockRoleHierarchy) IsRoleInherited(userRoles []string, targetRole string) bool {
	args := m.Called(userRoles, targetRole)
	return args.Bool(0)
}

func (m *MockRoleHierarchy) GetInheritedPermissions(roles []string) []string {
	args := m.Called(roles)
	return args.Get(0).([]string)
}

func createTestClaims() *interfaces.Claims {
	return &interfaces.Claims{
		UserID:      "user123",
		Email:       "test@example.com",
		Roles:       []string{"user", "manager"},
		Permissions: []string{"users:read", "users:write", "projects:read"},
		ExpiresAt:   9999999999,
		IssuedAt:    1000000000,
		Subject:     "user123",
		Issuer:      "test-issuer",
	}
}

func TestDefaultPolicyEngine_CheckPermission(t *testing.T) {
	tests := []struct {
		name                  string
		permission            string
		userPermissions       []string
		inheritedPermissions  []string
		cachedPermissions     []string
		superAdminRole        string
		userRoles            []string
		enableHierarchy      bool
		expectedResult       bool
		expectCacheCall      bool
		expectHierarchyCall  bool
	}{
		{
			name:            "Direct permission match",
			permission:      "users:read",
			userPermissions: []string{"users:read", "users:write"},
			expectedResult:  true,
		},
		{
			name:            "No permission match",
			permission:      "admin:write",
			userPermissions: []string{"users:read", "users:write"},
			expectedResult:  false,
		},
		{
			name:            "Super admin role",
			permission:      "admin:write",
			userPermissions: []string{"users:read"},
			userRoles:       []string{"super_admin"},
			superAdminRole:  "super_admin",
			expectedResult:  true,
		},
		{
			name:                 "Inherited permission",
			permission:           "projects:write",
			userPermissions:      []string{"users:read"},
			inheritedPermissions: []string{"projects:write", "reports:read"},
			enableHierarchy:      true,
			expectedResult:       true,
			expectHierarchyCall:  true,
		},
		{
			name:            "Wildcard permission match",
			permission:      "users:delete",
			userPermissions: []string{"users:*", "projects:read"},
			expectedResult:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockCache := new(MockCacheService)
			mockHierarchy := new(MockRoleHierarchy)

			// Setup config
			config := &interfaces.RBACConfig{
				EnableHierarchy: tt.enableHierarchy,
				SuperAdminRole:  tt.superAdminRole,
				CacheTTL:       300,
			}

			// Create policy engine
			pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, config)

			// Create claims
			claims := createTestClaims()
			claims.Permissions = tt.userPermissions
			if len(tt.userRoles) > 0 {
				claims.Roles = tt.userRoles
			}

			// Setup hierarchy mock expectations
			if tt.expectHierarchyCall {
				mockHierarchy.On("GetInheritedPermissions", claims.Roles).
					Return(tt.inheritedPermissions)
			}

			// Setup cache mock expectations for cache miss
			if !tt.expectedResult && len(tt.cachedPermissions) == 0 {
				mockCache.On("Get", mock.Anything, "rbac:permissions:user123").
					Return([]byte{}, interfaces.ErrCacheKeyNotFound)
			}

			// Execute
			ctx := context.Background()
			result, err := pe.CheckPermission(ctx, claims.UserID, tt.permission, claims)

			// Assert
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)

			mockCache.AssertExpectations(t)
			mockHierarchy.AssertExpectations(t)
		})
	}
}

func TestDefaultPolicyEngine_CheckRole(t *testing.T) {
	tests := []struct {
		name            string
		targetRole      string
		userRoles       []string
		enableHierarchy bool
		isInherited     bool
		expectedResult  bool
	}{
		{
			name:           "Direct role match",
			targetRole:     "manager",
			userRoles:      []string{"user", "manager"},
			expectedResult: true,
		},
		{
			name:           "No role match",
			targetRole:     "admin",
			userRoles:      []string{"user", "manager"},
			expectedResult: false,
		},
		{
			name:            "Inherited role",
			targetRole:      "admin",
			userRoles:       []string{"manager"},
			enableHierarchy: true,
			isInherited:     true,
			expectedResult:  true,
		},
		{
			name:            "Not inherited role",
			targetRole:      "admin",
			userRoles:       []string{"manager"},
			enableHierarchy: true,
			isInherited:     false,
			expectedResult:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockCache := new(MockCacheService)
			mockHierarchy := new(MockRoleHierarchy)

			// Setup config
			config := &interfaces.RBACConfig{
				EnableHierarchy: tt.enableHierarchy,
				CacheTTL:       300,
			}

			// Create policy engine
			pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, config)

			// Create claims
			claims := createTestClaims()
			claims.Roles = tt.userRoles

			// Setup hierarchy mock expectations
			if tt.enableHierarchy {
				mockHierarchy.On("IsRoleInherited", tt.userRoles, tt.targetRole).
					Return(tt.isInherited)
			}

			// Execute
			ctx := context.Background()
			result, err := pe.CheckRole(ctx, claims.UserID, tt.targetRole, claims)

			// Assert
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)

			mockCache.AssertExpectations(t)
			mockHierarchy.AssertExpectations(t)
		})
	}
}

func TestDefaultPolicyEngine_CheckAnyPermission(t *testing.T) {
	// Setup mocks
	mockCache := new(MockCacheService)
	mockHierarchy := new(MockRoleHierarchy)

	config := &interfaces.RBACConfig{
		EnableHierarchy: false,
		CacheTTL:       300,
	}

	pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, config)
	claims := createTestClaims()
	claims.Permissions = []string{"users:read", "projects:read"}

	ctx := context.Background()

	t.Run("Has one of multiple permissions", func(t *testing.T) {
		permissions := []string{"users:read", "admin:write"}
		result, err := pe.CheckAnyPermission(ctx, claims.UserID, permissions, claims)
		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("Has none of the permissions", func(t *testing.T) {
		permissions := []string{"admin:read", "admin:write"}
		
		// Setup cache mock for cache miss
		mockCache.On("Get", mock.Anything, "rbac:permissions:user123").
			Return([]byte{}, interfaces.ErrCacheKeyNotFound).Times(2)

		result, err := pe.CheckAnyPermission(ctx, claims.UserID, permissions, claims)
		assert.NoError(t, err)
		assert.False(t, result)
	})

	mockCache.AssertExpectations(t)
}

func TestDefaultPolicyEngine_CheckAllPermissions(t *testing.T) {
	// Setup mocks
	mockCache := new(MockCacheService)
	mockHierarchy := new(MockRoleHierarchy)

	config := &interfaces.RBACConfig{
		EnableHierarchy: false,
		CacheTTL:       300,
	}

	pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, config)
	claims := createTestClaims()
	claims.Permissions = []string{"users:read", "users:write", "projects:read"}

	ctx := context.Background()

	t.Run("Has all permissions", func(t *testing.T) {
		permissions := []string{"users:read", "projects:read"}
		result, err := pe.CheckAllPermissions(ctx, claims.UserID, permissions, claims)
		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("Missing some permissions", func(t *testing.T) {
		permissions := []string{"users:read", "admin:write"}
		
		// Setup cache mock for cache miss on admin:write
		mockCache.On("Get", mock.Anything, "rbac:permissions:user123").
			Return([]byte{}, interfaces.ErrCacheKeyNotFound)

		result, err := pe.CheckAllPermissions(ctx, claims.UserID, permissions, claims)
		assert.NoError(t, err)
		assert.False(t, result)
	})

	mockCache.AssertExpectations(t)
}

func TestDefaultPolicyEngine_GetUserPermissions(t *testing.T) {
	// Setup mocks
	mockCache := new(MockCacheService)
	mockHierarchy := new(MockRoleHierarchy)

	config := &interfaces.RBACConfig{
		EnableHierarchy: true,
		CacheTTL:       300,
	}

	pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, config)
	claims := createTestClaims()
	claims.Permissions = []string{"users:read", "users:write"}
	claims.Roles = []string{"manager"}

	inheritedPermissions := []string{"projects:read", "reports:read", "users:read"} // users:read is duplicate

	// Setup hierarchy mock
	mockHierarchy.On("GetInheritedPermissions", claims.Roles).
		Return(inheritedPermissions)

	// Setup cache mock for async caching
	mockCache.On("Set", mock.Anything, "rbac:permissions:user123", mock.Anything, time.Duration(300)*time.Second).
		Return(nil)

	ctx := context.Background()
	result, err := pe.GetUserPermissions(ctx, claims.UserID, claims)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, result, 4) // users:read, users:write, projects:read, reports:read (deduplicated)
	assert.Contains(t, result, "users:read")
	assert.Contains(t, result, "users:write")
	assert.Contains(t, result, "projects:read")
	assert.Contains(t, result, "reports:read")

	// Give some time for async cache operation
	time.Sleep(10 * time.Millisecond)

	mockCache.AssertExpectations(t)
	mockHierarchy.AssertExpectations(t)
}

func TestDefaultPolicyEngine_GetUserRoles(t *testing.T) {
	// Setup mocks
	mockCache := new(MockCacheService)
	mockHierarchy := new(MockRoleHierarchy)

	config := &interfaces.RBACConfig{
		EnableHierarchy: true,
		CacheTTL:       300,
	}

	pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, config)
	claims := createTestClaims()
	claims.Roles = []string{"manager", "user"}

	// Setup hierarchy mock
	mockHierarchy.On("GetParentRoles", "manager").Return([]string{"admin"})
	mockHierarchy.On("GetParentRoles", "user").Return([]string{"guest"})

	ctx := context.Background()
	result, err := pe.GetUserRoles(ctx, claims.UserID, claims)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, result, 4) // manager, user, admin, guest
	assert.Contains(t, result, "manager")
	assert.Contains(t, result, "user")
	assert.Contains(t, result, "admin")
	assert.Contains(t, result, "guest")

	mockHierarchy.AssertExpectations(t)
}

func TestDefaultPolicyEngine_RefreshUserPermissions(t *testing.T) {
	// Setup mocks
	mockCache := new(MockCacheService)
	mockHierarchy := new(MockRoleHierarchy)

	pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, nil)

	// Setup cache mock
	mockCache.On("Delete", mock.Anything, "rbac:permissions:user123").
		Return(nil)

	ctx := context.Background()
	err := pe.RefreshUserPermissions(ctx, "user123")

	// Assert
	assert.NoError(t, err)
	mockCache.AssertExpectations(t)
}

func TestDefaultPolicyEngine_getCachedPermissions(t *testing.T) {
	// Setup mocks
	mockCache := new(MockCacheService)
	mockHierarchy := new(MockRoleHierarchy)

	pe := NewDefaultPolicyEngine(mockCache, mockHierarchy, nil)

	t.Run("Cache hit", func(t *testing.T) {
		permissions := []string{"users:read", "projects:write"}
		data, _ := json.Marshal(permissions)

		mockCache.On("Get", mock.Anything, "rbac:permissions:user123").
			Return(data, nil)

		ctx := context.Background()
		result, err := pe.getCachedPermissions(ctx, "user123")

		assert.NoError(t, err)
		assert.Equal(t, permissions, result)
	})

	t.Run("Cache miss", func(t *testing.T) {
		mockCache.On("Get", mock.Anything, "rbac:permissions:user456").
			Return([]byte{}, interfaces.ErrCacheKeyNotFound)

		ctx := context.Background()
		result, err := pe.getCachedPermissions(ctx, "user456")

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	mockCache.AssertExpectations(t)
}

func TestDefaultPolicyEngine_hasPermission(t *testing.T) {
	pe := NewDefaultPolicyEngine(nil, nil, nil)

	tests := []struct {
		name        string
		permissions []string
		target      string
		expected    bool
	}{
		{
			name:        "Exact match",
			permissions: []string{"users:read", "projects:write"},
			target:      "users:read",
			expected:    true,
		},
		{
			name:        "No match",
			permissions: []string{"users:read", "projects:write"},
			target:      "admin:write",
			expected:    false,
		},
		{
			name:        "Wildcard match",
			permissions: []string{"users:*", "projects:read"},
			target:      "users:delete",
			expected:    true,
		},
		{
			name:        "Wildcard no match",
			permissions: []string{"users:*", "projects:read"},
			target:      "admin:delete",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pe.hasPermission(tt.permissions, tt.target)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultPolicyEngine_hasRole(t *testing.T) {
	pe := NewDefaultPolicyEngine(nil, nil, nil)

	tests := []struct {
		name     string
		roles    []string
		target   string
		expected bool
	}{
		{
			name:     "Role exists",
			roles:    []string{"user", "manager", "admin"},
			target:   "manager",
			expected: true,
		},
		{
			name:     "Role does not exist",
			roles:    []string{"user", "manager"},
			target:   "admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pe.hasRole(tt.roles, tt.target)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultPolicyEngine_cacheUserPermissions(t *testing.T) {
	mockCache := new(MockCacheService)
	config := &interfaces.RBACConfig{CacheTTL: 300}
	pe := NewDefaultPolicyEngine(mockCache, nil, config)

	permissions := []string{"users:read", "projects:write"}
	expectedData, _ := json.Marshal(permissions)
	expectedTTL := time.Duration(300) * time.Second

	mockCache.On("Set", mock.Anything, "rbac:permissions:user123", expectedData, expectedTTL).
		Return(nil)

	ctx := context.Background()
	pe.cacheUserPermissions(ctx, "user123", permissions)

	// Give some time for async operation
	time.Sleep(10 * time.Millisecond)

	mockCache.AssertExpectations(t)
}