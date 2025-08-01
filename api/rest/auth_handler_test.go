package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"erp-api-gateway/internal/interfaces"
	authpb "erp-api-gateway/proto/gen/auth"
)

// Mock implementations
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

func (m *MockAuthServiceClient) Login(ctx context.Context, req *authpb.LoginRequest, opts ...grpc.CallOption) (*authpb.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.LoginResponse), args.Error(1)
}

func (m *MockAuthServiceClient) Register(ctx context.Context, req *authpb.RegisterRequest, opts ...grpc.CallOption) (*authpb.RegisterResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.RegisterResponse), args.Error(1)
}

func (m *MockAuthServiceClient) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest, opts ...grpc.CallOption) (*authpb.RefreshTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.RefreshTokenResponse), args.Error(1)
}

func (m *MockAuthServiceClient) RevokeToken(ctx context.Context, req *authpb.RevokeTokenRequest, opts ...grpc.CallOption) (*authpb.RevokeTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.RevokeTokenResponse), args.Error(1)
}

func (m *MockAuthServiceClient) GetUser(ctx context.Context, req *authpb.GetUserRequest, opts ...grpc.CallOption) (*authpb.GetUserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.GetUserResponse), args.Error(1)
}

func (m *MockAuthServiceClient) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest, opts ...grpc.CallOption) (*authpb.ValidateTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authpb.ValidateTokenResponse), args.Error(1)
}

func (m *MockAuthServiceClient) UpdateUser(ctx context.Context, req *authpb.UpdateUserRequest, opts ...grpc.CallOption) (*authpb.UpdateUserResponse, error) {
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

// Test setup helper
func setupAuthHandlerTest() (*AuthHandler, *MockGRPCClient, *MockCacheService, *MockEventPublisher, *MockLogger) {
	mockGRPCClient := &MockGRPCClient{}
	mockCacheService := &MockCacheService{}
	mockEventPublisher := &MockEventPublisher{}
	mockLogger := &MockLogger{}

	handler := NewAuthHandler(mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger)
	
	return handler, mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger
}

// Test Login endpoint
func TestAuthHandler_Login_Success(t *testing.T) {
	handler, mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger := setupAuthHandlerTest()
	
	// Setup mocks
	mockAuthClient := &MockAuthServiceClient{}
	mockGRPCClient.On("AuthService", mock.Anything).Return(mockAuthClient, nil)
	
	now := time.Now()
	grpcResponse := &authpb.LoginResponse{
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
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
		},
	}
	
	mockAuthClient.On("Login", mock.Anything, mock.MatchedBy(func(req *authpb.LoginRequest) bool {
		return req.Email == "john@example.com" && req.Password == "password123"
	})).Return(grpcResponse, nil)
	
	mockCacheService.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, CacheTTLUserProfile).Return(nil)
	mockEventPublisher.On("PublishUserEvent", mock.Anything, "user-123", mock.AnythingOfType("interfaces.Event")).Return(nil)
	mockLogger.On("LogInfo", mock.Anything, mock.AnythingOfType("string"), mock.Anything)

	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login/", handler.Login)

	// Create request
	loginReq := LoginRequest{
		Email:      "john@example.com",
		Password:   "password123",
		RememberMe: false,
	}
	
	reqBody, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/login/", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	
	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Login successful", response.Message)
	
	// Verify auth data
	authData, ok := response.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "access-token", authData["access_token"])
	assert.Equal(t, "refresh-token", authData["refresh_token"])
	
	// Verify mocks were called
	mockGRPCClient.AssertExpectations(t)
	mockAuthClient.AssertExpectations(t)
	mockCacheService.AssertExpectations(t)
	mockEventPublisher.AssertExpectations(t)
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	handler, mockGRPCClient, _, _, _ := setupAuthHandlerTest()
	
	// Setup mocks
	mockAuthClient := &MockAuthServiceClient{}
	mockGRPCClient.On("AuthService", mock.Anything).Return(mockAuthClient, nil)
	
	grpcResponse := &authpb.LoginResponse{
		Success: false,
		Message: "Invalid credentials",
		Errors: map[string]*authpb.FieldErrors{
			"email": {Errors: []string{"Invalid email or password"}},
		},
	}
	
	mockAuthClient.On("Login", mock.Anything, mock.Anything).Return(grpcResponse, nil)

	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login/", handler.Login)

	// Create request
	loginReq := LoginRequest{
		Email:    "john@example.com",
		Password: "wrongpassword",
	}
	
	reqBody, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/login/", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	
	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, "Invalid credentials", response.Message)
	assert.Contains(t, response.Errors["email"], "Invalid email or password")
	
	// Verify mocks were called
	mockGRPCClient.AssertExpectations(t)
	mockAuthClient.AssertExpectations(t)
}

func TestAuthHandler_Login_ServiceUnavailable(t *testing.T) {
	handler, mockGRPCClient, _, _, mockLogger := setupAuthHandlerTest()
	
	// Setup mocks
	mockGRPCClient.On("AuthService", mock.Anything).Return(nil, errors.New("service unavailable"))
	mockLogger.On("LogError", mock.Anything, mock.AnythingOfType("string"), mock.Anything)

	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login/", handler.Login)

	// Create request
	loginReq := LoginRequest{
		Email:    "john@example.com",
		Password: "password123",
	}
	
	reqBody, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/login/", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	
	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	
	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, "Authentication service is currently unavailable", response.Message)
	
	// Verify mocks were called
	mockGRPCClient.AssertExpectations(t)
}

// Test Register endpoint
func TestAuthHandler_Register_Success(t *testing.T) {
	handler, mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger := setupAuthHandlerTest()
	
	// Setup mocks
	mockAuthClient := &MockAuthServiceClient{}
	mockGRPCClient.On("AuthService", mock.Anything).Return(mockAuthClient, nil)
	
	now := time.Now()
	grpcResponse := &authpb.RegisterResponse{
		Success: true,
		Message: "Registration successful",
		Data: &authpb.AuthData{
			User: &authpb.User{
				Id:        "user-123",
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john@example.com",
				CreatedAt: timestamppb.New(now),
				UpdatedAt: timestamppb.New(now),
			},
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
		},
	}
	
	mockAuthClient.On("Register", mock.Anything, mock.MatchedBy(func(req *authpb.RegisterRequest) bool {
		return req.Email == "john@example.com" && req.FirstName == "John"
	})).Return(grpcResponse, nil)
	
	mockCacheService.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, CacheTTLUserProfile).Return(nil)
	mockEventPublisher.On("PublishUserEvent", mock.Anything, "user-123", mock.AnythingOfType("interfaces.Event")).Return(nil)
	mockLogger.On("LogInfo", mock.Anything, mock.AnythingOfType("string"), mock.Anything)

	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/register/", handler.Register)

	// Create request
	registerReq := RegisterRequest{
		FirstName:            "John",
		LastName:             "Doe",
		Email:                "john@example.com",
		Password:             "password123",
		PasswordConfirmation: "password123",
	}
	
	reqBody, _ := json.Marshal(registerReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/register/", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	
	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)
	
	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Registration successful", response.Message)
	
	// Verify mocks were called
	mockGRPCClient.AssertExpectations(t)
	mockAuthClient.AssertExpectations(t)
	mockCacheService.AssertExpectations(t)
	mockEventPublisher.AssertExpectations(t)
}

func TestAuthHandler_Register_PasswordMismatch(t *testing.T) {
	handler, _, _, _, _ := setupAuthHandlerTest()

	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/register/", handler.Register)

	// Create request with mismatched passwords
	registerReq := RegisterRequest{
		FirstName:            "John",
		LastName:             "Doe",
		Email:                "john@example.com",
		Password:             "password123",
		PasswordConfirmation: "differentpassword",
	}
	
	reqBody, _ := json.Marshal(registerReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/register/", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	
	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, "Validation failed", response.Message)
	assert.Contains(t, response.Errors["password_confirmation"], "Password confirmation does not match")
}

// Test GetCurrentUser endpoint
func TestAuthHandler_GetCurrentUser_Success(t *testing.T) {
	handler, mockGRPCClient, mockCacheService, _, _ := setupAuthHandlerTest()
	
	// Setup mocks
	mockAuthClient := &MockAuthServiceClient{}
	mockGRPCClient.On("AuthService", mock.Anything).Return(mockAuthClient, nil)
	
	// Mock cache miss first
	mockCacheService.On("Get", mock.Anything, "user_profile:user-123").Return(nil, interfaces.ErrCacheKeyNotFound)
	
	now := time.Now()
	grpcResponse := &authpb.GetUserResponse{
		Success: true,
		Message: "User found",
		Data: &authpb.User{
			Id:        "user-123",
			FirstName: "John",
			LastName:  "Doe",
			Email:     "john@example.com",
			CreatedAt: timestamppb.New(now),
			UpdatedAt: timestamppb.New(now),
		},
	}
	
	mockAuthClient.On("GetUser", mock.Anything, mock.MatchedBy(func(req *authpb.GetUserRequest) bool {
		return req.UserId == "user-123"
	})).Return(grpcResponse, nil)
	
	mockCacheService.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, CacheTTLUserProfile).Return(nil)

	// Setup Gin with user context
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Next()
	})
	router.GET("/auth/me/", handler.GetCurrentUser)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/auth/me/", nil)
	
	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "User profile retrieved", response.Message)
	
	// Verify user data
	userData, ok := response.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "user-123", userData["id"])
	assert.Equal(t, "John", userData["first_name"])
	assert.Equal(t, "john@example.com", userData["email"])
	
	// Verify mocks were called
	mockGRPCClient.AssertExpectations(t)
	mockAuthClient.AssertExpectations(t)
	mockCacheService.AssertExpectations(t)
}

func TestAuthHandler_GetCurrentUser_Unauthenticated(t *testing.T) {
	handler, _, _, _, _ := setupAuthHandlerTest()

	// Setup Gin without user context
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/me/", handler.GetCurrentUser)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/auth/me/", nil)
	
	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, "User not authenticated", response.Message)
}

// Test helper methods
func TestAuthHandler_ConvertUser(t *testing.T) {
	handler, _, _, _, _ := setupAuthHandlerTest()
	
	now := time.Now()
	emailVerified := time.Now().Add(-24 * time.Hour)
	
	grpcUser := &authpb.User{
		Id:              "user-123",
		FirstName:       "John",
		LastName:        "Doe",
		Email:           "john@example.com",
		EmailVerifiedAt: timestamppb.New(emailVerified),
		CreatedAt:       timestamppb.New(now),
		UpdatedAt:       timestamppb.New(now),
	}
	
	user := handler.convertUser(grpcUser)
	
	assert.Equal(t, "user-123", user.ID)
	assert.Equal(t, "John", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)
	assert.Equal(t, "john@example.com", user.Email)
	assert.NotNil(t, user.EmailVerifiedAt)
	assert.Equal(t, emailVerified.Unix(), user.EmailVerifiedAt.Unix())
	assert.Equal(t, now.Unix(), user.CreatedAt.Unix())
	assert.Equal(t, now.Unix(), user.UpdatedAt.Unix())
}

func TestAuthHandler_ConvertGRPCErrors(t *testing.T) {
	handler, _, _, _, _ := setupAuthHandlerTest()
	
	grpcErrors := map[string]*authpb.FieldErrors{
		"email": {
			Errors: []string{"Email is required", "Email format is invalid"},
		},
		"password": {
			Errors: []string{"Password is too short"},
		},
	}
	
	errors := handler.convertGRPCErrors(grpcErrors)
	
	assert.Len(t, errors, 2)
	assert.Contains(t, errors["email"], "Email is required")
	assert.Contains(t, errors["email"], "Email format is invalid")
	assert.Contains(t, errors["password"], "Password is too short")
}