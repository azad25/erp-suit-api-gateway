package server

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock implementations for testing
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) LogRequest(ctx context.Context, entry interfaces.RequestLogEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockLogger) LogError(ctx context.Context, entry interfaces.ErrorLogEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockLogger) LogEvent(ctx context.Context, entry interfaces.EventLogEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockLogger) LogMetric(ctx context.Context, entry interfaces.MetricLogEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockLogger) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockJWTValidator struct {
	mock.Mock
}

func (m *MockJWTValidator) ValidateToken(token string) (*interfaces.Claims, error) {
	args := m.Called(token)
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

func createTestConfig() *config.Config {
	// Create a minimal test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:            8080,
			Host:            "localhost",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 10 * time.Second,
			CORS: config.CORSConfig{
				AllowedOrigins:   []string{"http://localhost:3000"},
				AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"Authorization", "Content-Type"},
				AllowCredentials: true,
				MaxAge:           86400,
			},
		},
		WebSocket: config.WebSocketConfig{
			ReadBufferSize:    4096,
			WriteBufferSize:   4096,
			HandshakeTimeout:  10 * time.Second,
			MaxConnections:    1000,
			AllowedOrigins:    []string{"http://localhost:3000"},
			EnableCompression: true,
		},
	}
	return cfg
}



func createTestDependencies() *Dependencies {
	mockLogger := &MockLogger{}
	mockJWTValidator := &MockJWTValidator{}
	mockPolicyEngine := &MockPolicyEngine{}

	// Set up mock expectations
	mockLogger.On("LogRequest", mock.Anything, mock.Anything).Return(nil)
	mockLogger.On("LogError", mock.Anything, mock.Anything).Return(nil)
	mockLogger.On("Close").Return(nil)

	return &Dependencies{
		Logger:        mockLogger,
		GRPCClient:    nil, // Not needed for basic tests
		RedisClient:   nil, // Nil to disable WebSocket handler
		KafkaProducer: nil, // Not needed for basic tests
		JWTValidator:  mockJWTValidator,
		PolicyEngine:  mockPolicyEngine,
	}
}

func TestServer_HealthCheck(t *testing.T) {
	cfg := createTestConfig()
	deps := createTestDependencies()
	
	server := New(cfg, deps)
	
	req, err := http.NewRequest("GET", "/health", nil)
	assert.NoError(t, err)
	
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "healthy")
}

func TestServer_ReadinessCheck(t *testing.T) {
	cfg := createTestConfig()
	deps := createTestDependencies()
	
	server := New(cfg, deps)
	
	req, err := http.NewRequest("GET", "/ready", nil)
	assert.NoError(t, err)
	
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	
	// Should return 200 even with nil dependencies for basic test
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "ready")
}

func TestServer_MetricsEndpoint(t *testing.T) {
	cfg := createTestConfig()
	deps := createTestDependencies()
	
	server := New(cfg, deps)
	
	req, err := http.NewRequest("GET", "/metrics", nil)
	assert.NoError(t, err)
	
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "http_requests_total")
}

func TestServer_CORSHeaders(t *testing.T) {
	cfg := createTestConfig()
	deps := createTestDependencies()
	
	server := New(cfg, deps)
	
	req, err := http.NewRequest("OPTIONS", "/health", nil)
	assert.NoError(t, err)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	
	// Check CORS headers are present
	assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestServer_GracefulShutdown(t *testing.T) {
	cfg := createTestConfig()
	deps := createTestDependencies()
	
	server := New(cfg, deps)
	
	// Test graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := server.Shutdown(ctx)
	assert.NoError(t, err)
}