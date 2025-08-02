package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"erp-api-gateway/internal/interfaces"
)

// MockJWTValidator is a mock implementation of JWTValidator
type MockJWTValidator struct {
	mock.Mock
}

func (m *MockJWTValidator) ValidateToken(token string) (*interfaces.Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*interfaces.Claims), args.Error(1)
}

func (m *MockJWTValidator) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	args := m.Called(keyID)
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

func (m *MockJWTValidator) RefreshJWKS() error {
	args := m.Called()
	return args.Error(0)
}

// MockCacheService is a mock implementation of CacheService (reused from jwt_validator_test.go)
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

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func createTestClaims() *interfaces.Claims {
	return &interfaces.Claims{
		UserID:      "test-user-id",
		Email:       "test@example.com",
		Roles:       []string{"user", "admin"},
		Permissions: []string{"read", "write"},
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
		IssuedAt:    time.Now().Unix(),
		Subject:     "test-user-id",
		Issuer:      "test-issuer",
	}
}

func TestAuthMiddleware_ValidateJWT(t *testing.T) {
	mockValidator := new(MockJWTValidator)
	mockCache := new(MockCacheService)
	middleware := NewAuthMiddleware(mockValidator, mockCache)

	t.Run("ValidToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		claims := createTestClaims()
		token := "valid-token"

		mockValidator.On("ValidateToken", token).Return(claims, nil)
		mockCache.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

		router.GET("/test", middleware.ValidateJWT(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "success", response["message"])

		mockValidator.AssertExpectations(t)
	})

	t.Run("MissingAuthorizationHeader", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		router.GET("/test", middleware.ValidateJWT(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Authorization header is required", response["message"])
	})

	t.Run("InvalidAuthorizationHeaderFormat", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		router.GET("/test", middleware.ValidateJWT(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Invalid token-format")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Invalid authorization header format", response["message"])
	})

	t.Run("EmptyToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		router.GET("/test", middleware.ValidateJWT(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer ")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Token is required", response["message"])
	})

	t.Run("InvalidToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		token := "invalid-token"
		
		mockValidator.On("ValidateToken", token).Return(nil, fmt.Errorf("token validation failed"))

		router.GET("/test", middleware.ValidateJWT(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Invalid token", response["message"])
		assert.Contains(t, response, "errors")

		mockValidator.AssertExpectations(t)
	})
}

func TestAuthMiddleware_OptionalJWT(t *testing.T) {
	mockValidator := new(MockJWTValidator)
	mockCache := new(MockCacheService)
	middleware := NewAuthMiddleware(mockValidator, mockCache)

	t.Run("ValidToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		claims := createTestClaims()
		token := "valid-token"

		mockValidator.On("ValidateToken", token).Return(claims, nil)
		mockCache.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

		router.GET("/test", middleware.OptionalJWT(), func(c *gin.Context) {
			userID, exists := GetUserID(c)
			if exists {
				c.JSON(http.StatusOK, gin.H{"user_id": userID})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "anonymous"})
			}
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "test-user-id", response["user_id"])

		mockValidator.AssertExpectations(t)
	})

	t.Run("NoToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		router.GET("/test", middleware.OptionalJWT(), func(c *gin.Context) {
			userID, exists := GetUserID(c)
			if exists {
				c.JSON(http.StatusOK, gin.H{"user_id": userID})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "anonymous"})
			}
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "anonymous", response["message"])
	})

	t.Run("InvalidToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		token := "invalid-token"
		
		mockValidator.On("ValidateToken", token).Return(nil, fmt.Errorf("token validation failed"))

		router.GET("/test", middleware.OptionalJWT(), func(c *gin.Context) {
			userID, exists := GetUserID(c)
			if exists {
				c.JSON(http.StatusOK, gin.H{"user_id": userID})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "anonymous"})
			}
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "anonymous", response["message"])

		mockValidator.AssertExpectations(t)
	})
}

func TestAuthMiddleware_ExtractClaims(t *testing.T) {
	mockValidator := new(MockJWTValidator)
	mockCache := new(MockCacheService)
	middleware := NewAuthMiddleware(mockValidator, mockCache)

	t.Run("ValidClaims", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		claims := createTestClaims()

		router.GET("/test", func(c *gin.Context) {
			// Simulate ValidateJWT middleware setting claims
			c.Set(UserClaimsKey, claims)
			c.Set(UserIDKey, claims.UserID)
		}, middleware.ExtractClaims(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("MissingClaims", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		router.GET("/test", middleware.ExtractClaims(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "User not authenticated", response["message"])
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		claims := createTestClaims()
		claims.ExpiresAt = time.Now().Add(-time.Hour).Unix() // Expired

		router.GET("/test", func(c *gin.Context) {
			// Simulate ValidateJWT middleware setting expired claims
			c.Set(UserClaimsKey, claims)
		}, middleware.ExtractClaims(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Token has expired", response["message"])
	})
}

func TestHelperFunctions(t *testing.T) {
	// Setup Gin context with test claims
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	claims := createTestClaims()
	
	c.Set(UserClaimsKey, claims)
	c.Set(UserIDKey, claims.UserID)
	c.Set(UserRolesKey, claims.Roles)
	c.Set(UserPermsKey, claims.Permissions)

	t.Run("GetUserClaims", func(t *testing.T) {
		userClaims, exists := GetUserClaims(c)
		assert.True(t, exists)
		assert.Equal(t, claims, userClaims)
	})

	t.Run("GetUserID", func(t *testing.T) {
		userID, exists := GetUserID(c)
		assert.True(t, exists)
		assert.Equal(t, "test-user-id", userID)
	})

	t.Run("GetUserRoles", func(t *testing.T) {
		roles, exists := GetUserRoles(c)
		assert.True(t, exists)
		assert.Equal(t, []string{"user", "admin"}, roles)
	})

	t.Run("GetUserPermissions", func(t *testing.T) {
		permissions, exists := GetUserPermissions(c)
		assert.True(t, exists)
		assert.Equal(t, []string{"read", "write"}, permissions)
	})

	t.Run("IsAuthenticated", func(t *testing.T) {
		assert.True(t, IsAuthenticated(c))
	})

	t.Run("HasRole", func(t *testing.T) {
		assert.True(t, HasRole(c, "user"))
		assert.True(t, HasRole(c, "admin"))
		assert.False(t, HasRole(c, "superuser"))
	})

	t.Run("HasPermission", func(t *testing.T) {
		assert.True(t, HasPermission(c, "read"))
		assert.True(t, HasPermission(c, "write"))
		assert.False(t, HasPermission(c, "delete"))
	})

	t.Run("HasAnyRole", func(t *testing.T) {
		assert.True(t, HasAnyRole(c, "user", "superuser"))
		assert.True(t, HasAnyRole(c, "admin"))
		assert.False(t, HasAnyRole(c, "superuser", "moderator"))
	})

	t.Run("HasAnyPermission", func(t *testing.T) {
		assert.True(t, HasAnyPermission(c, "read", "delete"))
		assert.True(t, HasAnyPermission(c, "write"))
		assert.False(t, HasAnyPermission(c, "delete", "admin"))
	})

	t.Run("HasAllRoles", func(t *testing.T) {
		assert.True(t, HasAllRoles(c, "user", "admin"))
		assert.True(t, HasAllRoles(c, "user"))
		assert.False(t, HasAllRoles(c, "user", "admin", "superuser"))
	})

	t.Run("HasAllPermissions", func(t *testing.T) {
		assert.True(t, HasAllPermissions(c, "read", "write"))
		assert.True(t, HasAllPermissions(c, "read"))
		assert.False(t, HasAllPermissions(c, "read", "write", "delete"))
	})
}

func TestHelperFunctions_NoAuth(t *testing.T) {
	// Setup Gin context without authentication
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	t.Run("GetUserClaims_NoAuth", func(t *testing.T) {
		userClaims, exists := GetUserClaims(c)
		assert.False(t, exists)
		assert.Nil(t, userClaims)
	})

	t.Run("GetUserID_NoAuth", func(t *testing.T) {
		userID, exists := GetUserID(c)
		assert.False(t, exists)
		assert.Empty(t, userID)
	})

	t.Run("IsAuthenticated_NoAuth", func(t *testing.T) {
		assert.False(t, IsAuthenticated(c))
	})

	t.Run("HasRole_NoAuth", func(t *testing.T) {
		assert.False(t, HasRole(c, "user"))
	})

	t.Run("HasPermission_NoAuth", func(t *testing.T) {
		assert.False(t, HasPermission(c, "read"))
	})
}

func TestAuthMiddleware_RequireAuth(t *testing.T) {
	mockValidator := new(MockJWTValidator)
	mockCache := new(MockCacheService)
	middleware := NewAuthMiddleware(mockValidator, mockCache)

	t.Run("ValidTokenAndClaims", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		claims := createTestClaims()
		token := "valid-token"

		mockValidator.On("ValidateToken", token).Return(claims, nil)
		mockCache.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

		router.GET("/test", middleware.RequireAuth(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		mockValidator.AssertExpectations(t)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		token := "invalid-token"
		
		mockValidator.On("ValidateToken", token).Return(nil, fmt.Errorf("token validation failed"))

		router.GET("/test", middleware.RequireAuth(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockValidator.AssertExpectations(t)
	})
}

func TestAuthMiddleware_ExtractClaims_InvalidClaims(t *testing.T) {
	mockValidator := new(MockJWTValidator)
	mockCache := new(MockCacheService)
	middleware := NewAuthMiddleware(mockValidator, mockCache)

	t.Run("InvalidClaimsType", func(t *testing.T) {
		// Setup
		router := setupTestRouter()
		router.GET("/test", func(c *gin.Context) {
			// Set invalid claims type
			c.Set(UserClaimsKey, "invalid-claims-type")
		}, middleware.ExtractClaims(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Invalid user claims", response["message"])
	})
}

func TestAuthMiddleware_CacheUserClaims(t *testing.T) {
	mockValidator := new(MockJWTValidator)
	mockCache := new(MockCacheService)
	middleware := NewAuthMiddleware(mockValidator, mockCache)

	t.Run("CacheWithNilCache", func(t *testing.T) {
		// Test with nil cache
		middlewareNilCache := NewAuthMiddleware(mockValidator, nil)
		claims := createTestClaims()
		
		// This should not panic
		middlewareNilCache.cacheUserClaims(claims)
	})

	t.Run("CacheWithExpiredToken", func(t *testing.T) {
		// Test with expired token
		claims := createTestClaims()
		claims.ExpiresAt = time.Now().Add(-time.Hour).Unix() // Expired
		
		// This should not cache anything
		middleware.cacheUserClaims(claims)
	})

	t.Run("CacheWithValidToken", func(t *testing.T) {
		// Test with valid token
		claims := createTestClaims()
		
		// Mock cache set operation
		mockCache.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.AnythingOfType("time.Duration")).Return(nil)
		
		middleware.cacheUserClaims(claims)
		
		// Give goroutine time to execute
		time.Sleep(10 * time.Millisecond)
		
		mockCache.AssertExpectations(t)
	})
}

func TestHelperFunctions_EdgeCases(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	t.Run("GetUserRoles_NoRoles", func(t *testing.T) {
		roles, exists := GetUserRoles(c)
		assert.False(t, exists)
		assert.Nil(t, roles)
	})

	t.Run("GetUserPermissions_NoPermissions", func(t *testing.T) {
		permissions, exists := GetUserPermissions(c)
		assert.False(t, exists)
		assert.Nil(t, permissions)
	})

	t.Run("GetUserRoles_InvalidType", func(t *testing.T) {
		c.Set(UserRolesKey, "invalid-type")
		roles, exists := GetUserRoles(c)
		assert.False(t, exists)
		assert.Nil(t, roles)
	})

	t.Run("GetUserPermissions_InvalidType", func(t *testing.T) {
		c.Set(UserPermsKey, "invalid-type")
		permissions, exists := GetUserPermissions(c)
		assert.False(t, exists)
		assert.Nil(t, permissions)
	})

	t.Run("GetUserID_InvalidType", func(t *testing.T) {
		c.Set(UserIDKey, 123) // Invalid type
		userID, exists := GetUserID(c)
		assert.False(t, exists)
		assert.Empty(t, userID)
	})

	t.Run("GetUserClaims_InvalidType", func(t *testing.T) {
		c.Set(UserClaimsKey, "invalid-type")
		claims, exists := GetUserClaims(c)
		assert.False(t, exists)
		assert.Nil(t, claims)
	})
}

func TestHelperFunctions_EmptyArrays(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	// Set empty arrays
	c.Set(UserRolesKey, []string{})
	c.Set(UserPermsKey, []string{})

	t.Run("HasAnyRole_EmptyRoles", func(t *testing.T) {
		assert.False(t, HasAnyRole(c, "user", "admin"))
	})

	t.Run("HasAnyPermission_EmptyPermissions", func(t *testing.T) {
		assert.False(t, HasAnyPermission(c, "read", "write"))
	})

	t.Run("HasAllRoles_EmptyRoles", func(t *testing.T) {
		assert.True(t, HasAllRoles(c)) // Empty array should return true for empty check
	})

	t.Run("HasAllPermissions_EmptyPermissions", func(t *testing.T) {
		assert.True(t, HasAllPermissions(c)) // Empty array should return true for empty check
	})
}

func TestAuthMiddleware_OptionalJWT_EdgeCases(t *testing.T) {
	mockValidator := new(MockJWTValidator)

	t.Run("OptionalJWT_WithCacheNil", func(t *testing.T) {
		// Setup middleware with nil cache
		middlewareNilCache := NewAuthMiddleware(mockValidator, nil)
		router := setupTestRouter()
		claims := createTestClaims()
		token := "valid-token"

		mockValidator.On("ValidateToken", token).Return(claims, nil)

		router.GET("/test", middlewareNilCache.OptionalJWT(), func(c *gin.Context) {
			userID, exists := GetUserID(c)
			if exists {
				c.JSON(http.StatusOK, gin.H{"user_id": userID})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "anonymous"})
			}
		})

		// Test
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "test-user-id", response["user_id"])

		mockValidator.AssertExpectations(t)
	})
}