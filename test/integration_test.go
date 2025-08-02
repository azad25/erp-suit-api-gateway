package test

import (
	"bytes"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	"erp-api-gateway/api/rest"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/middleware"
	authpb "erp-api-gateway/proto/gen/auth"
)

// Mock implementations for integration tests
type MockGRPCClient struct {
	mock.Mock
}

func (m *MockGRPCClient) AuthService(ctx context.Context) (authpb.AuthServiceClient, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(authpb.AuthServiceClient), args.Error(1)
}

type MockAuthServiceClient struct {
	mock.Mock
}

func (m *MockAuthServiceClient) Login(ctx context.Context, req *authpb.LoginRequest, opts ...interface{}) (*authpb.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.LoginResponse), args.Error(1)
}

func (m *MockAuthServiceClient) Register(ctx context.Context, req *authpb.RegisterRequest, opts ...interface{}) (*authpb.RegisterResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.RegisterResponse), args.Error(1)
}

func (m *MockAuthServiceClient) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest, opts ...interface{}) (*authpb.RefreshTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.RefreshTokenResponse), args.Error(1)
}

func (m *MockAuthServiceClient) RevokeToken(ctx context.Context, req *authpb.RevokeTokenRequest, opts ...interface{}) (*authpb.RevokeTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.RevokeTokenResponse), args.Error(1)
}

func (m *MockAuthServiceClient) GetUser(ctx context.Context, req *authpb.GetUserRequest, opts ...interface{}) (*authpb.GetUserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.GetUserResponse), args.Error(1)
}

func (m *MockAuthServiceClient) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest, opts ...interface{}) (*authpb.ValidateTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.ValidateTokenResponse), args.Error(1)
}

func (m *MockAuthServiceClient) UpdateUser(ctx context.Context, req *authpb.UpdateUserRequest, opts ...interface{}) (*authpb.UpdateUserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.UpdateUserResponse), args.Error(1)
}

type MockCacheService struct {
	mock.Mock
}

func (m *MockCacheService) Get(ctx context.Context, key string) ([]byte, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
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

type MockEventPublisher struct {
	mock.Mock
}

func (m *MockEventPublisher) PublishEvent(ctx context.Context, event interfaces.Event) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockEventPublisher) PublishUserEvent(ctx context.Context, userID string, event interfaces.Event) error {
	args := m.Called(ctx, userID, event)
	return args.Error(0)
}

func (m *MockEventPublisher) PublishBatch(ctx context.Context, events []interfaces.Event) error {
	args := m.Called(ctx, events)
	return args.Error(0)
}

func (m *MockEventPublisher) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) LogInfo(ctx context.Context, message string, fields map[string]interface{}) {
	m.Called(ctx, message, fields)
}

func (m *MockLogger) LogWarning(ctx context.Context, message string, fields map[string]interface{}) {
	m.Called(ctx, message, fields)
}

func (m *MockLogger) LogError(ctx context.Context, message string, fields map[string]interface{}) {
	m.Called(ctx, message, fields)
}

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
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

func (m *MockJWTValidator) RefreshJWKS() error {
	args := m.Called()
	return args.Error(0)
}

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

// Integration test setup
func setupIntegrationTest() (*gin.Engine, *MockGRPCClient, *MockCacheService, *MockEventPublisher, *MockLogger, *MockJWTValidator, *MockPolicyEngine) {
	gin.SetMode(gin.TestMode)
	
	// Create mocks
	mockGRPCClient := &MockGRPCClient{}
	mockCacheService := &MockCacheService{}
	mockEventPublisher := &MockEventPublisher{}
	mockLogger := &MockLogger{}
	mockJWTValidator := &MockJWTValidator{}
	mockPolicyEngine := &MockPolicyEngine{}

	// Create router
	router := gin.New()

	// Setup middleware
	authMiddleware := middleware.NewAuthMiddleware(mockJWTValidator, mockCacheService)
	rbacMiddleware := middleware.NewRBACMiddleware(mockPolicyEngine, nil)

	// Setup handlers
	authHandler := rest.NewAuthHandler(mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger)

	// Setup routes
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login/", authHandler.Login)
		authGroup.POST("/register/", authHandler.Register)
		authGroup.GET("/me/", authMiddleware.ValidateJWT(), authHandler.GetCurrentUser)
		authGroup.POST("/logout/", authMiddleware.ValidateJWT(), authHandler.Logout)
		authGroup.POST("/refresh/", authHandler.RefreshToken)
	}

	// Protected routes
	protectedGroup := router.Group("/api")
	protectedGroup.Use(authMiddleware.ValidateJWT())
	{
		protectedGroup.GET("/profile", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "profile data"})
		})
		
		adminGroup := protectedGroup.Group("/admin")
		adminGroup.Use(rbacMiddleware.RequireRole("admin"))
		{
			adminGroup.GET("/users", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "admin users data"})
			})
		}
	}

	return router, mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger, mockJWTValidator, mockPolicyEngine
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

// Integration Tests

func TestIntegration_CompleteAuthFlow(t *testing.T) {
	router, mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger, _, _ := setupIntegrationTest()

	t.Run("Login -> Access Protected Resource -> Logout", func(t *testing.T) {
		// Setup mocks for login
		mockAuthClient := &MockAuthServiceClient{}
		mockGRPCClient.On("AuthService", mock.Anything).Return(mockAuthClient, nil)

		now := time.Now()
		loginResponse := &authpb.LoginResponse{
			Success: true,
			Message: "Login successful",
			Data: &authpb.AuthData{
				User: &authpb.User{
					Id:        "user-123",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "john@example.com",
					CreatedAt: timestamppb.New(now),
					UpdatedAt: timestamppb.New(now),
				},
				AccessToken:  "access-token-123",
				RefreshToken: "refresh-token-123",
				ExpiresIn:    3600,
			},
		}

		mockAuthClient.On("Login", mock.Anything, mock.Anything).Return(loginResponse, nil)
		mockCacheService.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)
		mockEventPublisher.On("PublishUserEvent", mock.Anything, "user-123", mock.AnythingOfType("interfaces.Event")).Return(nil)
		mockLogger.On("LogInfo", mock.Anything, mock.AnythingOfType("string"), mock.Anything)

		// Step 1: Login
		loginReq := map[string]interface{}{
			"email":    "john@example.com",
			"password": "password123",
		}
		reqBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/auth/login/", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var loginResp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &loginResp)
		assert.NoError(t, err)
		assert.True(t, loginResp["success"].(bool))

		// Extract access token
		data := loginResp["data"].(map[string]interface{})
		accessToken := data["access_token"].(string)
		assert.NotEmpty(t, accessToken)

		// Step 2: Access protected resource (this would normally validate the token)
		// For this test, we'll simulate the token validation
		req2 := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
		req2.Header.Set("Authorization", "Bearer "+accessToken)
		w2 := httptest.NewRecorder()
		
		// Note: In a real scenario, the JWT validator would validate the token
		// For this integration test, we're focusing on the flow structure
		router.ServeHTTP(w2, req2)

		// Step 3: Logout
		mockAuthClient.On("RevokeToken", mock.Anything, mock.Anything).Return(&authpb.RevokeTokenResponse{
			Success: true,
			Message: "Logout successful",
		}, nil)
		mockCacheService.On("Delete", mock.Anything, mock.AnythingOfType("string")).Return(nil)
		mockEventPublisher.On("PublishUserEvent", mock.Anything, "user-123", mock.AnythingOfType("interfaces.Event")).Return(nil)

		req3 := httptest.NewRequest(http.MethodPost, "/auth/logout/", nil)
		req3.Header.Set("Authorization", "Bearer "+accessToken)
		w3 := httptest.NewRecorder()
		router.ServeHTTP(w3, req3)

		// Verify all mocks were called as expected
		mockGRPCClient.AssertExpectations(t)
		mockAuthClient.AssertExpectations(t)
		mockCacheService.AssertExpectations(t)
		mockEventPublisher.AssertExpectations(t)
	})
}

func TestIntegration_AuthenticationAndAuthorization(t *testing.T) {
	router, _, _, _, _, mockJWTValidator, mockPolicyEngine := setupIntegrationTest()

	t.Run("Valid Token with Admin Role", func(t *testing.T) {
		// Setup JWT validation
		claims := createTestClaims()
		mockJWTValidator.On("ValidateToken", "valid-admin-token").Return(claims, nil)
		
		// Setup RBAC check
		mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, "admin", claims).Return(true, nil)

		// Access admin endpoint
		req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer valid-admin-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "admin users data", response["message"])

		mockJWTValidator.AssertExpectations(t)
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("Valid Token without Admin Role", func(t *testing.T) {
		// Setup JWT validation
		claims := createTestClaims()
		claims.Roles = []string{"user"} // Remove admin role
		mockJWTValidator.On("ValidateToken", "valid-user-token").Return(claims, nil)
		
		// Setup RBAC check
		mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, "admin", claims).Return(false, nil)

		// Access admin endpoint
		req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer valid-user-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.False(t, response["success"].(bool))
		assert.Equal(t, "Insufficient role", response["message"])

		mockJWTValidator.AssertExpectations(t)
		mockPolicyEngine.AssertExpectations(t)
	})

	t.Run("Invalid Token", func(t *testing.T) {
		// Setup JWT validation failure
		mockJWTValidator.On("ValidateToken", "invalid-token").Return(nil, fmt.Errorf("token validation failed"))

		// Access protected endpoint
		req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.False(t, response["success"].(bool))
		assert.Equal(t, "Invalid token", response["message"])

		mockJWTValidator.AssertExpectations(t)
	})

	t.Run("No Token", func(t *testing.T) {
		// Access protected endpoint without token
		req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.False(t, response["success"].(bool))
		assert.Equal(t, "Authorization header is required", response["message"])
	})
}

func TestIntegration_ErrorHandling(t *testing.T) {
	router, mockGRPCClient, _, _, mockLogger, _, _ := setupIntegrationTest()

	t.Run("Service Unavailable", func(t *testing.T) {
		// Setup service unavailable error
		mockGRPCClient.On("AuthService", mock.Anything).Return(nil, fmt.Errorf("service unavailable"))
		mockLogger.On("LogError", mock.Anything, mock.AnythingOfType("string"), mock.Anything)

		// Attempt login
		loginReq := map[string]interface{}{
			"email":    "john@example.com",
			"password": "password123",
		}
		reqBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/auth/login/", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.False(t, response["success"].(bool))
		assert.Equal(t, "Authentication service is currently unavailable", response["message"])

		mockGRPCClient.AssertExpectations(t)
		mockLogger.AssertExpectations(t)
	})
}

func TestIntegration_CacheIntegration(t *testing.T) {
	router, mockGRPCClient, mockCacheService, _, _, mockJWTValidator, _ := setupIntegrationTest()

	t.Run("Cache Hit for User Profile", func(t *testing.T) {
		// Setup JWT validation
		claims := createTestClaims()
		mockJWTValidator.On("ValidateToken", "valid-token").Return(claims, nil)
		
		// Setup cache hit
		cachedUser := `{"id":"test-user-id","first_name":"John","last_name":"Doe","email":"test@example.com"}`
		mockCacheService.On("Get", mock.Anything, "user_profile:test-user-id").Return([]byte(cachedUser), nil)

		// Access user profile endpoint
		req := httptest.NewRequest(http.MethodGet, "/auth/me/", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockJWTValidator.AssertExpectations(t)
		mockCacheService.AssertExpectations(t)
		
		// Verify gRPC was not called due to cache hit
		mockGRPCClient.AssertNotCalled(t, "AuthService")
	})

	t.Run("Cache Miss - Fetch from Service", func(t *testing.T) {
		// Setup JWT validation
		claims := createTestClaims()
		mockJWTValidator.On("ValidateToken", "valid-token-2").Return(claims, nil)
		
		// Setup cache miss
		mockCacheService.On("Get", mock.Anything, "user_profile:test-user-id").Return(nil, interfaces.ErrCacheKeyNotFound)
		
		// Setup gRPC call
		mockAuthClient := &MockAuthServiceClient{}
		mockGRPCClient.On("AuthService", mock.Anything).Return(mockAuthClient, nil)
		
		now := time.Now()
		userResponse := &authpb.GetUserResponse{
			Success: true,
			Message: "User found",
			Data: &authpb.User{
				Id:        "test-user-id",
				FirstName: "John",
				LastName:  "Doe",
				Email:     "test@example.com",
				CreatedAt: timestamppb.New(now),
				UpdatedAt: timestamppb.New(now),
			},
		}
		
		mockAuthClient.On("GetUser", mock.Anything, mock.Anything).Return(userResponse, nil)
		mockCacheService.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

		// Access user profile endpoint
		req := httptest.NewRequest(http.MethodGet, "/auth/me/", nil)
		req.Header.Set("Authorization", "Bearer valid-token-2")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockJWTValidator.AssertExpectations(t)
		mockCacheService.AssertExpectations(t)
		mockGRPCClient.AssertExpectations(t)
		mockAuthClient.AssertExpectations(t)
	})
}