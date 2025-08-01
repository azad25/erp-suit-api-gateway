package middleware

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"erp-api-gateway/internal/interfaces"
)

// MockLogger is a mock implementation of the Logger interface
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

func TestNewLoggingMiddleware(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	assert.NotNil(t, middleware)
	assert.Equal(t, mockLogger, middleware.logger)
}

func TestLoggingMiddleware_RequestLogger(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	// Set up expectations
	mockLogger.On("LogRequest", mock.Anything, mock.MatchedBy(func(entry interfaces.RequestLogEntry) bool {
		return entry.Method == "GET" &&
			entry.Path == "/test" &&
			entry.StatusCode == 200 &&
			entry.RequestID != ""
	})).Return(nil)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.RequestLogger())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, 200, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestLoggingMiddleware_RequestLoggerWithUserID(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	// Set up expectations
	mockLogger.On("LogRequest", mock.Anything, mock.MatchedBy(func(entry interfaces.RequestLogEntry) bool {
		return entry.UserID == "user123"
	})).Return(nil)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.RequestLogger())
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", "user123")
		c.JSON(200, gin.H{"message": "success"})
	})

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestLoggingMiddleware_RequestLoggerWithRequestID(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	// Set up expectations
	mockLogger.On("LogRequest", mock.Anything, mock.MatchedBy(func(entry interfaces.RequestLogEntry) bool {
		return entry.RequestID == "custom-request-id"
	})).Return(nil)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.RequestLogger())
	router.GET("/test", func(c *gin.Context) {
		// Verify the request ID is set in the context
		requestID, exists := c.Get("request_id")
		assert.True(t, exists)
		assert.Equal(t, "custom-request-id", requestID)
		c.JSON(200, gin.H{"message": "success"})
	})

	// Make request with custom request ID
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "custom-request-id")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestLoggingMiddleware_RequestLoggerWithBody(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	requestBody := `{"name":"test"}`

	// Set up expectations
	mockLogger.On("LogRequest", mock.Anything, mock.MatchedBy(func(entry interfaces.RequestLogEntry) bool {
		return entry.Method == "POST" &&
			entry.RequestSize == int64(len(requestBody))
	})).Return(nil)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.RequestLogger())
	router.POST("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	// Make request with body
	req := httptest.NewRequest("POST", "/test", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestLoggingMiddleware_ErrorLogger(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	// Set up expectations
	mockLogger.On("LogRequest", mock.Anything, mock.Anything).Return(nil)
	mockLogger.On("LogError", mock.Anything, mock.MatchedBy(func(entry interfaces.ErrorLogEntry) bool {
		return entry.Level == interfaces.LogLevelError &&
			entry.Message == "test error" &&
			entry.Service == "erp-api-gateway" &&
			entry.Component == "middleware"
	})).Return(nil)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.RequestLogger())
	router.Use(middleware.ErrorLogger())
	router.GET("/test", func(c *gin.Context) {
		c.Error(errors.New("test error"))
		c.JSON(500, gin.H{"error": "internal error"})
	})

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestLoggingMiddleware_PanicRecovery(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	// Set up expectations
	mockLogger.On("LogError", mock.Anything, mock.MatchedBy(func(entry interfaces.ErrorLogEntry) bool {
		return entry.Level == interfaces.LogLevelFatal &&
			entry.Message == "Panic recovered" &&
			strings.Contains(entry.Error, "test panic")
	})).Return(nil)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.PanicRecovery())
	router.GET("/test", func(c *gin.Context) {
		panic("test panic")
	})

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, 500, w.Code)

	// Wait for logging
	time.Sleep(100 * time.Millisecond)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestResponseWriter(t *testing.T) {
	// Set up Gin test mode
	gin.SetMode(gin.TestMode)
	
	// Create a test context with a recorder
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	buffer := &bytes.Buffer{}
	responseWriter := &responseWriter{
		ResponseWriter: c.Writer,
		body:          buffer,
	}

	// Test Write
	data := []byte("test data")
	n, err := responseWriter.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, "test data", buffer.String())

	// Test WriteString
	buffer.Reset()
	n, err = responseWriter.WriteString("test string")
	assert.NoError(t, err)
	assert.Equal(t, len("test string"), n)
	assert.Equal(t, "test string", buffer.String())
}

func TestLoggingMiddleware_ExtractHeaders(t *testing.T) {
	middleware := &LoggingMiddleware{}

	headers := map[string][]string{
		"Content-Type":    {"application/json"},
		"Authorization":   {"Bearer token"}, // Should be excluded
		"User-Agent":      {"test-agent"},
		"X-Request-ID":    {"request-123"},
		"Accept":          {"application/json"},
		"Custom-Header":   {"custom-value"}, // Should be excluded
	}

	result := middleware.extractHeaders(headers)

	// Should include allowed headers
	assert.Equal(t, "application/json", result["Content-Type"])
	assert.Equal(t, "test-agent", result["User-Agent"])
	assert.Equal(t, "request-123", result["X-Request-ID"])
	assert.Equal(t, "application/json", result["Accept"])

	// Should exclude sensitive/unknown headers
	assert.NotContains(t, result, "Authorization")
	assert.NotContains(t, result, "Custom-Header")
}

func TestLoggingMiddleware_ExtractQueryParams(t *testing.T) {
	middleware := &LoggingMiddleware{}

	params := map[string][]string{
		"page":     {"1"},
		"limit":    {"10"},
		"password": {"secret"}, // Should be excluded
		"token":    {"abc123"}, // Should be excluded
		"search":   {"test query"},
	}

	result := middleware.extractQueryParams(params)

	// Should include safe parameters
	assert.Equal(t, "1", result["page"])
	assert.Equal(t, "10", result["limit"])
	assert.Equal(t, "test query", result["search"])

	// Should exclude sensitive parameters
	assert.NotContains(t, result, "password")
	assert.NotContains(t, result, "token")
}

func TestLoggingMiddleware_GetErrorLevel(t *testing.T) {
	middleware := &LoggingMiddleware{}

	tests := []struct {
		errorType gin.ErrorType
		expected  string
	}{
		{gin.ErrorTypeBind, interfaces.LogLevelWarn},
		{gin.ErrorTypePublic, interfaces.LogLevelInfo},
		{gin.ErrorTypePrivate, interfaces.LogLevelError},
		{gin.ErrorTypeRender, interfaces.LogLevelError},
		{gin.ErrorType(999), interfaces.LogLevelError}, // Unknown type
	}

	for _, tt := range tests {
		result := middleware.getErrorLevel(tt.errorType)
		assert.Equal(t, tt.expected, result)
	}
}

func TestShouldLogRequestBody(t *testing.T) {
	tests := []struct {
		method   string
		expected bool
	}{
		{"GET", false},
		{"POST", true},
		{"PUT", true},
		{"PATCH", true},
		{"DELETE", false},
		{"HEAD", false},
		{"OPTIONS", false},
	}

	for _, tt := range tests {
		result := shouldLogRequestBody(tt.method)
		assert.Equal(t, tt.expected, result, "Method: %s", tt.method)
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2) // Should be unique
	assert.Contains(t, id1, "-") // Should contain separator
}

func TestLoggingMiddleware_LogEvent(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	// Set up expectations
	mockLogger.On("LogEvent", mock.Anything, mock.MatchedBy(func(entry interfaces.EventLogEntry) bool {
		return entry.EventType == "user_login" &&
			entry.UserID == "user123" &&
			entry.Source == "erp-api-gateway" &&
			entry.Success == true
	})).Return(nil)

	// Create a Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("request_id", "req123")

	// Log event
	data := map[string]interface{}{"ip": "127.0.0.1"}
	err := middleware.LogEvent(c, "user_login", "user123", data)
	assert.NoError(t, err)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestLoggingMiddleware_LogMetric(t *testing.T) {
	mockLogger := &MockLogger{}
	middleware := NewLoggingMiddleware(mockLogger)

	// Set up expectations
	mockLogger.On("LogMetric", mock.Anything, mock.MatchedBy(func(entry interfaces.MetricLogEntry) bool {
		return entry.MetricName == "response_time" &&
			entry.MetricType == "gauge" &&
			entry.Value == 123.45
	})).Return(nil)

	// Create a Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Log metric
	labels := map[string]string{"endpoint": "/api/test"}
	err := middleware.LogMetric(c, "response_time", 123.45, labels)
	assert.NoError(t, err)

	// Verify mock expectations
	mockLogger.AssertExpectations(t)
}

func TestStructuredLogger(t *testing.T) {
	mockLogger := &MockLogger{}
	structuredLogger := NewStructuredLogger(mockLogger)

	// Set up Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("request_id", "req123")
	c.Set("user_id", "user456")

	t.Run("Info", func(t *testing.T) {
		mockLogger.On("LogError", mock.Anything, mock.MatchedBy(func(entry interfaces.ErrorLogEntry) bool {
			return entry.Level == interfaces.LogLevelInfo &&
				entry.Message == "test info" &&
				entry.RequestID == "req123" &&
				entry.UserID == "user456"
		})).Return(nil)

		fields := map[string]interface{}{"key": "value"}
		structuredLogger.Info(c, "test info", fields)

		// Wait for async logging
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("Warn", func(t *testing.T) {
		mockLogger.On("LogError", mock.Anything, mock.MatchedBy(func(entry interfaces.ErrorLogEntry) bool {
			return entry.Level == interfaces.LogLevelWarn &&
				entry.Message == "test warning"
		})).Return(nil)

		fields := map[string]interface{}{"key": "value"}
		structuredLogger.Warn(c, "test warning", fields)

		// Wait for async logging
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("Error", func(t *testing.T) {
		testErr := errors.New("test error")
		mockLogger.On("LogError", mock.Anything, mock.MatchedBy(func(entry interfaces.ErrorLogEntry) bool {
			return entry.Level == interfaces.LogLevelError &&
				entry.Message == "test error message" &&
				entry.Error == "test error"
		})).Return(nil)

		fields := map[string]interface{}{"key": "value"}
		structuredLogger.Error(c, "test error message", testErr, fields)

		// Wait for synchronous logging
		time.Sleep(50 * time.Millisecond)
	})

	// Verify all expectations
	mockLogger.AssertExpectations(t)
}

func TestLoggingMiddleware_GetCorrelationID(t *testing.T) {
	middleware := &LoggingMiddleware{}

	// Set up Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	t.Run("WithCorrelationID", func(t *testing.T) {
		c.Set("correlation_id", "corr123")
		correlationID := middleware.getCorrelationID(c)
		assert.Equal(t, "corr123", correlationID)
	})

	t.Run("WithRequestID", func(t *testing.T) {
		// Clear correlation_id and set request_id
		c.Keys = make(map[string]interface{})
		c.Set("request_id", "req123")
		correlationID := middleware.getCorrelationID(c)
		assert.Equal(t, "req123", correlationID)
	})

	t.Run("WithoutIDs", func(t *testing.T) {
		// Clear all keys
		c.Keys = make(map[string]interface{})
		correlationID := middleware.getCorrelationID(c)
		assert.Equal(t, "", correlationID)
	})
}

func TestStructuredLogger_GetRequestID(t *testing.T) {
	structuredLogger := &StructuredLogger{}

	// Set up Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	t.Run("WithRequestID", func(t *testing.T) {
		c.Set("request_id", "req123")
		requestID := structuredLogger.getRequestID(c)
		assert.Equal(t, "req123", requestID)
	})

	t.Run("WithoutRequestID", func(t *testing.T) {
		c.Keys = make(map[string]interface{})
		requestID := structuredLogger.getRequestID(c)
		assert.Equal(t, "", requestID)
	})
}

func TestStructuredLogger_GetUserID(t *testing.T) {
	structuredLogger := &StructuredLogger{}

	// Set up Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	t.Run("WithUserID", func(t *testing.T) {
		c.Set("user_id", "user123")
		userID := structuredLogger.getUserID(c)
		assert.Equal(t, "user123", userID)
	})

	t.Run("WithoutUserID", func(t *testing.T) {
		c.Keys = make(map[string]interface{})
		userID := structuredLogger.getUserID(c)
		assert.Equal(t, "", userID)
	})
}