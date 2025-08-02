package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"erp-api-gateway/internal/interfaces"
)

// MockPolicyEngine is a mock implementation of PolicyEngine
type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) CheckPermission(ctx context.Context, userID string, permission string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, permission, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckRole(ctx context.Context, userID string, role string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, role, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAnyPermission(ctx context.Context, userID string, permissions []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, permissions, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAllPermissions(ctx context.Context, userID string, permissions []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, permissions, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAnyRole(ctx context.Context, userID string, roles []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, roles, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAllRoles(ctx context.Context, userID string, roles []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, roles, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) GetUserPermissions(ctx context.Context, userID string, claims *interfaces.Claims) ([]string, error) {
	args := m.Called(ctx, userID, claims)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockPolicyEngine) GetUserRoles(ctx context.Context, userID string, claims *interfaces.Claims) ([]string, error) {
	args := m.Called(ctx, userID, claims)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockPolicyEngine) RefreshUserPermissions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func setupRBACTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func createRBACTestClaims() *interfaces.Claims {
	return &interfaces.Claims{
		UserID:      "user123",
		Email:       "test@example.com",
		Roles:       []string{"user", "manager"},
		Permissions: []string{"users:read", "users:write", "projects:read"},
		ExpiresAt:   9999999999, // Far future
		IssuedAt:    1000000000,
		Subject:     "user123",
		Issuer:      "test-issuer",
	}
}

func TestRBACMiddleware_RequirePermission(t *testing.T) {
	tests := []struct {
		name           string
		permission     string
		setupClaims    bool
		hasPermission  bool
		permissionErr  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid permission",
			permission:     "users:read",
			setupClaims:    true,
			hasPermission:  true,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "Missing permission",
			permission:     "admin:write",
			setupClaims:    true,
			hasPermission:  false,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions",
		},
		{
			name:           "No authentication",
			permission:     "users:read",
			setupClaims:    false,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authentication required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockPolicyEngine := new(MockPolicyEngine)
			rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
			router := setupRBACTestRouter()

			// Setup mock expectations
			if tt.setupClaims {
				claims := createRBACTestClaims()
				mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, tt.permission, claims).
					Return(tt.hasPermission, tt.permissionErr)
			}

			// Setup route
			router.Use(func(c *gin.Context) {
				if tt.setupClaims {
					claims := createRBACTestClaims()
					c.Set(UserClaimsKey, claims)
				}
				c.Next()
			})
			router.GET("/test", rbacMiddleware.RequirePermission(tt.permission), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Execute request
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			mockPolicyEngine.AssertExpectations(t)
		})
	}
}

func TestRBACMiddleware_RequireRole(t *testing.T) {
	tests := []struct {
		name           string
		role           string
		setupClaims    bool
		hasRole        bool
		roleErr        error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid role",
			role:           "manager",
			setupClaims:    true,
			hasRole:        true,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "Missing role",
			role:           "admin",
			setupClaims:    true,
			hasRole:        false,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient role",
		},
		{
			name:           "No authentication",
			role:           "user",
			setupClaims:    false,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authentication required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockPolicyEngine := new(MockPolicyEngine)
			rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
			router := setupRBACTestRouter()

			// Setup mock expectations
			if tt.setupClaims {
				claims := createRBACTestClaims()
				mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, tt.role, claims).
					Return(tt.hasRole, tt.roleErr)
			}

			// Setup route
			router.Use(func(c *gin.Context) {
				if tt.setupClaims {
					claims := createRBACTestClaims()
					c.Set(UserClaimsKey, claims)
				}
				c.Next()
			})
			router.GET("/test", rbacMiddleware.RequireRole(tt.role), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Execute request
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			mockPolicyEngine.AssertExpectations(t)
		})
	}
}

func TestRBACMiddleware_RequireAnyPermission(t *testing.T) {
	tests := []struct {
		name           string
		permissions    []string
		setupClaims    bool
		hasAny         bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Has one of multiple permissions",
			permissions:    []string{"users:read", "admin:write"},
			setupClaims:    true,
			hasAny:         true,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "Missing all permissions",
			permissions:    []string{"admin:read", "admin:write"},
			setupClaims:    true,
			hasAny:         false,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockPolicyEngine := new(MockPolicyEngine)
			rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
			router := setupRBACTestRouter()

			// Setup mock expectations
			if tt.setupClaims {
				claims := createRBACTestClaims()
				mockPolicyEngine.On("CheckAnyPermission", mock.Anything, claims.UserID, tt.permissions, claims).
					Return(tt.hasAny, nil)
			}

			// Setup route
			router.Use(func(c *gin.Context) {
				if tt.setupClaims {
					claims := createRBACTestClaims()
					c.Set(UserClaimsKey, claims)
				}
				c.Next()
			})
			router.GET("/test", rbacMiddleware.RequireAnyPermission(tt.permissions...), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Execute request
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			mockPolicyEngine.AssertExpectations(t)
		})
	}
}

func TestRBACMiddleware_RequireResourcePermission(t *testing.T) {
	tests := []struct {
		name           string
		resource       string
		action         string
		setupClaims    bool
		hasPermission  bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid resource permission",
			resource:       "users",
			action:         "read",
			setupClaims:    true,
			hasPermission:  true,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "Missing resource permission",
			resource:       "admin",
			action:         "write",
			setupClaims:    true,
			hasPermission:  false,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockPolicyEngine := new(MockPolicyEngine)
			config := &interfaces.RBACConfig{
				PermissionFormat: "resource:action",
			}
			rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, config)
			router := setupRBACTestRouter()

			// Setup mock expectations
			if tt.setupClaims {
				claims := createRBACTestClaims()
				expectedPermission := tt.resource + ":" + tt.action
				mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, expectedPermission, claims).
					Return(tt.hasPermission, nil)
			}

			// Setup route
			router.Use(func(c *gin.Context) {
				if tt.setupClaims {
					claims := createRBACTestClaims()
					c.Set(UserClaimsKey, claims)
				}
				c.Next()
			})
			router.GET("/test", rbacMiddleware.RequireResourcePermission(tt.resource, tt.action), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Execute request
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			mockPolicyEngine.AssertExpectations(t)
		})
	}
}

func TestRBACMiddleware_RequireSuperAdmin(t *testing.T) {
	// Setup
	mockPolicyEngine := new(MockPolicyEngine)
	config := &interfaces.RBACConfig{
		SuperAdminRole: "super_admin",
	}
	rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, config)
	router := setupRBACTestRouter()

	claims := createRBACTestClaims()
	mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, "super_admin", claims).
		Return(true, nil)

	// Setup route
	router.Use(func(c *gin.Context) {
		c.Set(UserClaimsKey, claims)
		c.Next()
	})
	router.GET("/test", rbacMiddleware.RequireSuperAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")

	mockPolicyEngine.AssertExpectations(t)
}

func TestRBACMiddleware_AllowGuest(t *testing.T) {
	// Setup
	mockPolicyEngine := new(MockPolicyEngine)
	rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
	router := setupRBACTestRouter()

	// Setup route (no authentication required)
	router.GET("/test", rbacMiddleware.AllowGuest(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

func TestRBACHelperFunctions(t *testing.T) {
	t.Run("CheckUserPermission", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		claims := createRBACTestClaims()

		mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, "users:read", claims).
			Return(true, nil)

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserPermission(c, mockPolicyEngine, "users:read")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("CheckUserRole", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		claims := createRBACTestClaims()

		mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, "manager", claims).
			Return(true, nil)

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserRole(c, mockPolicyEngine, "manager")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})
}

func TestFormatPermission(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		action   string
		format   string
		expected string
	}{
		{
			name:     "Resource:Action format",
			resource: "users",
			action:   "read",
			format:   "resource:action",
			expected: "users:read",
		},
		{
			name:     "Resource.Action format",
			resource: "users",
			action:   "read",
			format:   "resource.action",
			expected: "users.read",
		},
		{
			name:     "Action_Resource format",
			resource: "users",
			action:   "read",
			format:   "action_resource",
			expected: "read_users",
		},
		{
			name:     "Default format",
			resource: "users",
			action:   "read",
			format:   "unknown",
			expected: "users:read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPermission(tt.resource, tt.action, tt.format)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePermission(t *testing.T) {
	tests := []struct {
		name               string
		permission         string
		format             string
		expectedResource   string
		expectedAction     string
	}{
		{
			name:             "Resource:Action format",
			permission:       "users:read",
			format:           "resource:action",
			expectedResource: "users",
			expectedAction:   "read",
		},
		{
			name:             "Resource.Action format",
			permission:       "users.read",
			format:           "resource.action",
			expectedResource: "users",
			expectedAction:   "read",
		},
		{
			name:             "Action_Resource format",
			permission:       "read_users",
			format:           "action_resource",
			expectedResource: "users",
			expectedAction:   "read",
		},
		{
			name:             "Invalid format",
			permission:       "invalid",
			format:           "resource:action",
			expectedResource: "invalid",
			expectedAction:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, action := ParsePermission(tt.permission, tt.format)
			assert.Equal(t, tt.expectedResource, resource)
			assert.Equal(t, tt.expectedAction, action)
		})
	}
}

func TestIsOwnerOrHasPermission(t *testing.T) {
	mockPolicyEngine := new(MockPolicyEngine)
	router := setupRBACTestRouter()
	claims := createRBACTestClaims()

	t.Run("User is owner", func(t *testing.T) {
		router.GET("/test1", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := IsOwnerOrHasPermission(c, mockPolicyEngine, claims.UserID, "admin:write")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("User is not owner but has permission", func(t *testing.T) {
		mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, "admin:write", claims).
			Return(true, nil)

		router.GET("/test2", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := IsOwnerOrHasPermission(c, mockPolicyEngine, "other_user", "admin:write")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})
}

func TestRBACMiddleware_RequireAllPermissions(t *testing.T) {
	tests := []struct {
		name           string
		permissions    []string
		setupClaims    bool
		hasAll         bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Has all permissions",
			permissions:    []string{"users:read", "users:write"},
			setupClaims:    true,
			hasAll:         true,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "Missing some permissions",
			permissions:    []string{"users:read", "admin:write"},
			setupClaims:    true,
			hasAll:         false,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockPolicyEngine := new(MockPolicyEngine)
			rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
			router := setupRBACTestRouter()

			// Setup mock expectations
			if tt.setupClaims {
				claims := createRBACTestClaims()
				mockPolicyEngine.On("CheckAllPermissions", mock.Anything, claims.UserID, tt.permissions, claims).
					Return(tt.hasAll, nil)
			}

			// Setup route
			router.Use(func(c *gin.Context) {
				if tt.setupClaims {
					claims := createRBACTestClaims()
					c.Set(UserClaimsKey, claims)
				}
				c.Next()
			})
			router.GET("/test", rbacMiddleware.RequireAllPermissions(tt.permissions...), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Execute request
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			mockPolicyEngine.AssertExpectations(t)
		})
	}
}

func TestRBACMiddleware_RequireAnyRole(t *testing.T) {
	tests := []struct {
		name           string
		roles          []string
		setupClaims    bool
		hasAny         bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Has one of multiple roles",
			roles:          []string{"user", "admin"},
			setupClaims:    true,
			hasAny:         true,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "Missing all roles",
			roles:          []string{"admin", "superuser"},
			setupClaims:    true,
			hasAny:         false,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockPolicyEngine := new(MockPolicyEngine)
			rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
			router := setupRBACTestRouter()

			// Setup mock expectations
			if tt.setupClaims {
				claims := createRBACTestClaims()
				mockPolicyEngine.On("CheckAnyRole", mock.Anything, claims.UserID, tt.roles, claims).
					Return(tt.hasAny, nil)
			}

			// Setup route
			router.Use(func(c *gin.Context) {
				if tt.setupClaims {
					claims := createRBACTestClaims()
					c.Set(UserClaimsKey, claims)
				}
				c.Next()
			})
			router.GET("/test", rbacMiddleware.RequireAnyRole(tt.roles...), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Execute request
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			mockPolicyEngine.AssertExpectations(t)
		})
	}
}

func TestRBACMiddleware_RequireAllRoles(t *testing.T) {
	tests := []struct {
		name           string
		roles          []string
		setupClaims    bool
		hasAll         bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Has all roles",
			roles:          []string{"user", "manager"},
			setupClaims:    true,
			hasAll:         true,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "Missing some roles",
			roles:          []string{"user", "admin"},
			setupClaims:    true,
			hasAll:         false,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient roles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockPolicyEngine := new(MockPolicyEngine)
			rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
			router := setupRBACTestRouter()

			// Setup mock expectations
			if tt.setupClaims {
				claims := createRBACTestClaims()
				mockPolicyEngine.On("CheckAllRoles", mock.Anything, claims.UserID, tt.roles, claims).
					Return(tt.hasAll, nil)
			}

			// Setup route
			router.Use(func(c *gin.Context) {
				if tt.setupClaims {
					claims := createRBACTestClaims()
					c.Set(UserClaimsKey, claims)
				}
				c.Next()
			})
			router.GET("/test", rbacMiddleware.RequireAllRoles(tt.roles...), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Execute request
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			mockPolicyEngine.AssertExpectations(t)
		})
	}
}

func TestRBACMiddleware_ConditionalPermission(t *testing.T) {
	mockPolicyEngine := new(MockPolicyEngine)
	rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
	router := setupRBACTestRouter()

	t.Run("Condition false - skip permission check", func(t *testing.T) {
		router.GET("/test1", rbacMiddleware.ConditionalPermission("admin:write", func(c *gin.Context) bool {
			return false // Condition is false
		}), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Condition true - apply permission check", func(t *testing.T) {
		claims := createRBACTestClaims()
		mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, "admin:write", claims).
			Return(true, nil)

		router.GET("/test2", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			c.Next()
		}, rbacMiddleware.ConditionalPermission("admin:write", func(c *gin.Context) bool {
			return true // Condition is true
		}), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})
}

func TestRBACMiddleware_ErrorHandling(t *testing.T) {
	t.Run("Permission check error", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
		router := setupRBACTestRouter()
		
		claims := createRBACTestClaims()
		mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, "users:read", claims).
			Return(false, fmt.Errorf("database error"))

		router.Use(func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			c.Next()
		})
		router.GET("/test", rbacMiddleware.RequirePermission("users:read"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Permission check failed")
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("Role check error", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		rbacMiddleware := NewRBACMiddleware(mockPolicyEngine, nil)
		router := setupRBACTestRouter()
		
		claims := createRBACTestClaims()
		mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, "admin", claims).
			Return(false, fmt.Errorf("database error"))

		router.Use(func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			c.Next()
		})
		router.GET("/test", rbacMiddleware.RequireRole("admin"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Role check failed")
		mockPolicyEngine.AssertExpectations(t)
	})
}

func TestRBACHelperFunctions_Extended(t *testing.T) {
	claims := createRBACTestClaims()

	t.Run("CheckUserAnyPermission", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		mockPolicyEngine.On("CheckAnyPermission", mock.Anything, claims.UserID, []string{"users:read", "admin:write"}, claims).
			Return(true, nil)

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserAnyPermission(c, mockPolicyEngine, "users:read", "admin:write")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("CheckUserAllPermissions", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		mockPolicyEngine.On("CheckAllPermissions", mock.Anything, claims.UserID, []string{"users:read", "users:write"}, claims).
			Return(true, nil)

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserAllPermissions(c, mockPolicyEngine, "users:read", "users:write")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("CheckUserAnyRole", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		mockPolicyEngine.On("CheckAnyRole", mock.Anything, claims.UserID, []string{"user", "admin"}, claims).
			Return(true, nil)

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserAnyRole(c, mockPolicyEngine, "user", "admin")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("CheckUserAllRoles", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		mockPolicyEngine.On("CheckAllRoles", mock.Anything, claims.UserID, []string{"user", "manager"}, claims).
			Return(true, nil)

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserAllRoles(c, mockPolicyEngine, "user", "manager")
			assert.True(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})
}

func TestRBACHelperFunctions_NoAuth(t *testing.T) {
	t.Run("CheckUserPermission_NoAuth", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		router.GET("/test", func(c *gin.Context) {
			result := CheckUserPermission(c, mockPolicyEngine, "users:read")
			assert.False(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("CheckUserRole_NoAuth", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		router.GET("/test", func(c *gin.Context) {
			result := CheckUserRole(c, mockPolicyEngine, "admin")
			assert.False(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRBACHelperFunctions_Errors(t *testing.T) {
	claims := createRBACTestClaims()

	t.Run("CheckUserPermission_Error", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, "users:read", claims).
			Return(false, fmt.Errorf("database error"))

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserPermission(c, mockPolicyEngine, "users:read")
			assert.False(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("CheckUserRole_Error", func(t *testing.T) {
		mockPolicyEngine := new(MockPolicyEngine)
		router := setupRBACTestRouter()
		
		mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, "admin", claims).
			Return(false, fmt.Errorf("database error"))

		router.GET("/test", func(c *gin.Context) {
			c.Set(UserClaimsKey, claims)
			result := CheckUserRole(c, mockPolicyEngine, "admin")
			assert.False(t, result)
			c.JSON(http.StatusOK, gin.H{"result": result})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockPolicyEngine.AssertExpectations(t)
	})
}