package ws

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// MockPubSubService is a mock implementation of PubSubService
type MockPubSubService struct {
	mock.Mock
}

func (m *MockPubSubService) Publish(ctx context.Context, channel string, message interface{}) error {
	args := m.Called(ctx, channel, message)
	return args.Error(0)
}

func (m *MockPubSubService) Subscribe(ctx context.Context, channels ...string) (interfaces.PubSubSubscription, error) {
	args := m.Called(ctx, channels)
	return args.Get(0).(interfaces.PubSubSubscription), args.Error(1)
}

func (m *MockPubSubService) Unsubscribe(ctx context.Context, channels ...string) error {
	args := m.Called(ctx, channels)
	return args.Error(0)
}

// MockPubSubSubscription is a mock implementation of PubSubSubscription
type MockPubSubSubscription struct {
	mock.Mock
	msgChan chan *interfaces.Message
}

func (m *MockPubSubSubscription) Channel() <-chan *interfaces.Message {
	if m.msgChan == nil {
		m.msgChan = make(chan *interfaces.Message, 10)
	}
	return m.msgChan
}

func (m *MockPubSubSubscription) Close() error {
	args := m.Called()
	if m.msgChan != nil {
		close(m.msgChan)
	}
	return args.Error(0)
}

// MockSimpleLogger is a mock implementation of SimpleLogger
type MockSimpleLogger struct {
	mock.Mock
}

func (m *MockSimpleLogger) LogInfo(ctx context.Context, message string, fields map[string]interface{}) {
	m.Called(ctx, message, fields)
}

func (m *MockSimpleLogger) LogWarning(ctx context.Context, message string, fields map[string]interface{}) {
	m.Called(ctx, message, fields)
}

func (m *MockSimpleLogger) LogError(ctx context.Context, message string, fields map[string]interface{}) {
	m.Called(ctx, message, fields)
}

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

func createTestConfig() *config.WebSocketConfig {
	return &config.WebSocketConfig{
		ReadBufferSize:    4096,
		WriteBufferSize:   4096,
		HandshakeTimeout:  10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Second,
		PongTimeout:       60 * time.Second,
		PingPeriod:        54 * time.Second,
		MaxMessageSize:    1024 * 1024,
		MaxConnections:    100,
		AllowedOrigins:    []string{"http://localhost:3000"},
		EnableCompression: true,
		CompressionLevel:  1,
	}
}

func TestNewHandler(t *testing.T) {
	cfg := createTestConfig()
	mockRedis := &MockPubSubService{}
	mockLogger := &MockSimpleLogger{}
	mockJWT := &MockJWTValidator{}
	
	// Mock Redis subscription
	mockSub := &MockPubSubSubscription{}
	mockRedis.On("Subscribe", mock.Anything, mock.AnythingOfType("[]string")).Return(mockSub, nil).Once()
	mockSub.On("Close").Return(nil).Once()
	
	// Allow any logging calls
	mockLogger.On("LogInfo", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogWarning", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	
	handler := NewHandler(cfg, mockRedis, mockLogger, mockJWT, nil)
	
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.manager)
	assert.Equal(t, cfg, handler.config)
	
	// Clean up
	handler.Close()
}

func TestHandler_AuthenticateConnection(t *testing.T) {
	cfg := createTestConfig()
	mockRedis := &MockPubSubService{}
	mockLogger := &MockSimpleLogger{}
	mockJWT := &MockJWTValidator{}
	
	// Mock Redis subscription
	mockSub := &MockPubSubSubscription{}
	mockRedis.On("Subscribe", mock.Anything, mock.AnythingOfType("[]string")).Return(mockSub, nil).Once()
	mockSub.On("Close").Return(nil).Once()
	
	// Allow any logging calls
	mockLogger.On("LogInfo", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogWarning", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	
	handler := NewHandler(cfg, mockRedis, mockLogger, mockJWT, nil)
	defer handler.Close()
	
	tests := []struct {
		name        string
		setupReq    func() *http.Request
		setupMocks  func()
		expectError bool
		expectedUID string
	}{
		{
			name: "Valid token in query parameter",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/ws?token=valid-token", nil)
				return req
			},
			setupMocks: func() {
				mockJWT.On("ValidateToken", "valid-token").Return(&interfaces.Claims{
					UserID: "user123",
					Email:  "test@example.com",
				}, nil).Once()
			},
			expectError: false,
			expectedUID: "user123",
		},
		{
			name: "Valid token in Authorization header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/ws", nil)
				req.Header.Set("Authorization", "Bearer valid-token")
				return req
			},
			setupMocks: func() {
				mockJWT.On("ValidateToken", "valid-token").Return(&interfaces.Claims{
					UserID: "user456",
					Email:  "test2@example.com",
				}, nil).Once()
			},
			expectError: false,
			expectedUID: "user456",
		},
		{
			name: "Missing token",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/ws", nil)
			},
			setupMocks:  func() {},
			expectError: true,
		},
		{
			name: "Invalid token",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/ws?token=invalid-token", nil)
				return req
			},
			setupMocks: func() {
				mockJWT.On("ValidateToken", "invalid-token").Return(nil, assert.AnError).Once()
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			req := tt.setupReq()
			userID, err := handler.authenticateConnection(req)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUID, userID)
			}
		})
	}
}

func TestHandler_PublishNotification(t *testing.T) {
	cfg := createTestConfig()
	mockRedis := &MockPubSubService{}
	mockLogger := &MockSimpleLogger{}
	mockJWT := &MockJWTValidator{}
	
	// Mock Redis subscription for handler initialization
	mockSub := &MockPubSubSubscription{}
	mockRedis.On("Subscribe", mock.Anything, mock.AnythingOfType("[]string")).Return(mockSub, nil).Once()
	mockSub.On("Close").Return(nil).Once()
	
	// Allow any logging calls
	mockLogger.On("LogInfo", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogWarning", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	
	handler := NewHandler(cfg, mockRedis, mockLogger, mockJWT, nil)
	defer handler.Close()
	
	ctx := context.Background()
	userID := "user123"
	notification := map[string]interface{}{
		"title":   "Test Notification",
		"message": "This is a test notification",
	}
	
	// Mock Redis publish - this is the actual test
	mockRedis.On("Publish", ctx, "notifications:user123", mock.MatchedBy(func(msg *interfaces.WebSocketMessage) bool {
		return msg.Type == interfaces.MessageTypeNotification &&
			msg.UserID == userID &&
			msg.Data["title"] == "Test Notification"
	})).Return(nil).Once()
	
	err := handler.PublishNotification(ctx, userID, notification)
	assert.NoError(t, err)
	
	// Only assert the Publish call, not Subscribe since that's part of initialization
	mockRedis.AssertCalled(t, "Publish", ctx, "notifications:user123", mock.Anything)
}

func TestHandler_HandleRedisMessage(t *testing.T) {
	cfg := createTestConfig()
	mockRedis := &MockPubSubService{}
	mockLogger := &MockSimpleLogger{}
	mockJWT := &MockJWTValidator{}
	
	// Mock Redis subscription
	mockSub := &MockPubSubSubscription{}
	mockRedis.On("Subscribe", mock.Anything, mock.AnythingOfType("[]string")).Return(mockSub, nil).Once()
	mockSub.On("Close").Return(nil).Once()
	
	// Allow any logging calls
	mockLogger.On("LogInfo", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogWarning", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	
	handler := NewHandler(cfg, mockRedis, mockLogger, mockJWT, nil)
	defer handler.Close()
	
	// Test user notification message
	wsMessage := &interfaces.WebSocketMessage{
		Type: interfaces.MessageTypeNotification,
		Data: map[string]interface{}{
			"title": "Test Notification",
		},
		UserID: "user123",
	}
	
	messageBytes, err := json.Marshal(wsMessage)
	require.NoError(t, err)
	
	redisMsg := &interfaces.Message{
		Channel: "notifications:user123",
		Payload: string(messageBytes),
	}
	
	// Since we don't have actual connections, this will just log that no connections exist
	err = handler.handleRedisMessage(redisMsg)
	assert.NoError(t, err)
}

// Integration test with actual WebSocket connection
func TestHandler_WebSocketIntegration(t *testing.T) {
	cfg := createTestConfig()
	mockRedis := &MockPubSubService{}
	mockLogger := &MockSimpleLogger{}
	mockJWT := &MockJWTValidator{}
	
	// Mock Redis subscription
	mockSub := &MockPubSubSubscription{}
	mockRedis.On("Subscribe", mock.Anything, mock.AnythingOfType("[]string")).Return(mockSub, nil).Once()
	mockSub.On("Close").Return(nil).Once()
	
	// Allow any logging calls
	mockLogger.On("LogInfo", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogWarning", mock.Anything, mock.Anything, mock.Anything).Maybe()
	mockLogger.On("LogError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	
	// Mock JWT validation
	mockJWT.On("ValidateToken", "valid-token").Return(&interfaces.Claims{
		UserID: "user123",
		Email:  "test@example.com",
	}, nil)
	
	handler := NewHandler(cfg, mockRedis, mockLogger, mockJWT, nil)
	defer handler.Close()
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := handler.HandleConnection(w, r)
		if err != nil {
			t.Logf("WebSocket connection error: %v", err)
		}
	}))
	defer server.Close()
	
	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?token=valid-token"
	
	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()
	
	// Give some time for connection to be established
	time.Sleep(100 * time.Millisecond)
	
	// Check that connection was added
	assert.Equal(t, 1, handler.GetConnectionCount())
	
	// Send a subscribe message
	subscribeMsg := interfaces.WebSocketMessage{
		Type: interfaces.MessageTypeSubscribe,
		Data: map[string]interface{}{
			"channel": "test-channel",
		},
	}
	
	err = conn.WriteJSON(subscribeMsg)
	assert.NoError(t, err)
	
	// Read acknowledgment
	var ackMsg interfaces.WebSocketMessage
	err = conn.ReadJSON(&ackMsg)
	assert.NoError(t, err)
	assert.Equal(t, interfaces.MessageTypeAck, ackMsg.Type)
	
	// Close connection
	conn.Close()
	
	// Give some time for cleanup
	time.Sleep(100 * time.Millisecond)
}