package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"erp-api-gateway/internal/interfaces"
)

// LoggingMiddleware provides request/response logging functionality
type LoggingMiddleware struct {
	logger interfaces.Logger
}

// NewLoggingMiddleware creates a new logging middleware
func NewLoggingMiddleware(logger interfaces.Logger) *LoggingMiddleware {
	return &LoggingMiddleware{
		logger: logger,
	}
}

// RequestLogger returns a middleware that logs all HTTP requests
func (m *LoggingMiddleware) RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Generate request ID if not present
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
			c.Header("X-Request-ID", requestID)
		}

		// Store request ID in context for other middleware/handlers
		c.Set("request_id", requestID)

		// Capture request body if needed (for POST/PUT/PATCH requests)
		var requestBody []byte
		var requestSize int64
		if c.Request.Body != nil && shouldLogRequestBody(c.Request.Method) {
			requestBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
			requestSize = int64(len(requestBody))
		} else {
			requestSize = c.Request.ContentLength
		}

		// Create a custom response writer to capture response data
		responseWriter := &responseWriter{
			ResponseWriter: c.Writer,
			body:          &bytes.Buffer{},
		}
		c.Writer = responseWriter

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Get user ID from context (set by auth middleware)
		userID, _ := c.Get("user_id")
		userIDStr := ""
		if userID != nil {
			userIDStr = fmt.Sprintf("%v", userID)
		}

		// Prepare log entry
		entry := interfaces.RequestLogEntry{
			Timestamp:    start,
			RequestID:    requestID,
			UserID:       userIDStr,
			Method:       c.Request.Method,
			Path:         c.Request.URL.Path,
			StatusCode:   c.Writer.Status(),
			Duration:     duration,
			UserAgent:    c.Request.UserAgent(),
			RemoteIP:     c.ClientIP(),
			RequestSize:  requestSize,
			ResponseSize: int64(responseWriter.body.Len()),
			Headers:      m.extractHeaders(c.Request.Header),
			QueryParams:  m.extractQueryParams(c.Request.URL.Query()),
		}

		// Log the request asynchronously
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := m.logger.LogRequest(ctx, entry); err != nil {
				// Log to stderr if elasticsearch logging fails
				fmt.Printf("Failed to log request: %v\n", err)
			}
		}()
	}
}

// ErrorLogger returns a middleware that logs errors
func (m *LoggingMiddleware) ErrorLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors
		if len(c.Errors) > 0 {
			requestID, _ := c.Get("request_id")
			requestIDStr := ""
			if requestID != nil {
				requestIDStr = fmt.Sprintf("%v", requestID)
			}

			userID, _ := c.Get("user_id")
			userIDStr := ""
			if userID != nil {
				userIDStr = fmt.Sprintf("%v", userID)
			}

			// Log each error
			for _, ginErr := range c.Errors {
				entry := interfaces.ErrorLogEntry{
					Timestamp: time.Now(),
					RequestID: requestIDStr,
					UserID:    userIDStr,
					Level:     m.getErrorLevel(ginErr.Type),
					Message:   ginErr.Error(),
					Error:     ginErr.Error(),
					Context: map[string]interface{}{
						"method":      c.Request.Method,
						"path":        c.Request.URL.Path,
						"status_code": c.Writer.Status(),
						"user_agent":  c.Request.UserAgent(),
						"remote_ip":   c.ClientIP(),
					},
					Service:   "erp-api-gateway",
					Component: "middleware",
				}

				// Log the error asynchronously
				go func(logEntry interfaces.ErrorLogEntry) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					if err := m.logger.LogError(ctx, logEntry); err != nil {
						// Log to stderr if elasticsearch logging fails
						fmt.Printf("Failed to log error: %v\n", err)
					}
				}(entry)
			}
		}
	}
}

// PanicRecovery returns a middleware that recovers from panics and logs them
func (m *LoggingMiddleware) PanicRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		requestID, _ := c.Get("request_id")
		requestIDStr := ""
		if requestID != nil {
			requestIDStr = fmt.Sprintf("%v", requestID)
		}

		userID, _ := c.Get("user_id")
		userIDStr := ""
		if userID != nil {
			userIDStr = fmt.Sprintf("%v", userID)
		}

		entry := interfaces.ErrorLogEntry{
			Timestamp: time.Now(),
			RequestID: requestIDStr,
			UserID:    userIDStr,
			Level:     interfaces.LogLevelFatal,
			Message:   "Panic recovered",
			Error:     fmt.Sprintf("%v", recovered),
			Context: map[string]interface{}{
				"method":      c.Request.Method,
				"path":        c.Request.URL.Path,
				"user_agent":  c.Request.UserAgent(),
				"remote_ip":   c.ClientIP(),
				"panic_value": recovered,
			},
			Service:   "erp-api-gateway",
			Component: "middleware",
		}

		// Log the panic synchronously to ensure it's captured
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := m.logger.LogError(ctx, entry); err != nil {
			// Log to stderr if elasticsearch logging fails
			fmt.Printf("Failed to log panic: %v\n", err)
		}

		// Return 500 Internal Server Error
		c.AbortWithStatus(500)
	})
}

// responseWriter wraps gin.ResponseWriter to capture response body
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	// Write to both the original writer and our buffer
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) WriteString(s string) (int, error) {
	// Write to both the original writer and our buffer
	w.body.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}

// extractHeaders extracts relevant headers for logging
func (m *LoggingMiddleware) extractHeaders(headers map[string][]string) map[string]string {
	result := make(map[string]string)
	
	// List of headers to log (excluding sensitive ones)
	headersToLog := []string{
		"Content-Type",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Cache-Control",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Request-ID",
		"User-Agent",
	}

	for _, header := range headersToLog {
		if values, exists := headers[header]; exists && len(values) > 0 {
			result[header] = values[0]
		}
	}

	return result
}

// extractQueryParams extracts query parameters for logging
func (m *LoggingMiddleware) extractQueryParams(params map[string][]string) map[string]string {
	result := make(map[string]string)
	
	// Exclude sensitive parameters
	sensitiveParams := map[string]bool{
		"password":      true,
		"token":         true,
		"access_token":  true,
		"refresh_token": true,
		"api_key":       true,
		"secret":        true,
	}

	for key, values := range params {
		if !sensitiveParams[strings.ToLower(key)] && len(values) > 0 {
			result[key] = values[0]
		}
	}

	return result
}

// getErrorLevel maps Gin error types to log levels
func (m *LoggingMiddleware) getErrorLevel(errorType gin.ErrorType) string {
	switch errorType {
	case gin.ErrorTypeBind:
		return interfaces.LogLevelWarn
	case gin.ErrorTypePublic:
		return interfaces.LogLevelInfo
	case gin.ErrorTypePrivate:
		return interfaces.LogLevelError
	case gin.ErrorTypeRender:
		return interfaces.LogLevelError
	default:
		return interfaces.LogLevelError
	}
}

// shouldLogRequestBody determines if request body should be logged
func shouldLogRequestBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	// Simple request ID generation using timestamp and random component
	now := time.Now()
	return fmt.Sprintf("%d-%d", now.UnixNano(), now.Nanosecond()%1000000)
}

// LogEvent logs a business event
func (m *LoggingMiddleware) LogEvent(ctx context.Context, eventType string, userID string, data map[string]interface{}) error {
	entry := interfaces.EventLogEntry{
		Timestamp:     time.Now(),
		EventID:       generateRequestID(), // Reuse the ID generator
		EventType:     eventType,
		UserID:        userID,
		CorrelationID: m.getCorrelationID(ctx),
		Source:        "erp-api-gateway",
		Data:          data,
		Success:       true,
	}

	return m.logger.LogEvent(ctx, entry)
}

// LogMetric logs a performance metric
func (m *LoggingMiddleware) LogMetric(ctx context.Context, metricName string, value float64, labels map[string]string) error {
	entry := interfaces.MetricLogEntry{
		Timestamp:  time.Now(),
		MetricName: metricName,
		MetricType: "gauge", // Default to gauge
		Value:      value,
		Labels:     labels,
	}

	return m.logger.LogMetric(ctx, entry)
}

// getCorrelationID extracts correlation ID from context
func (m *LoggingMiddleware) getCorrelationID(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if correlationID, exists := ginCtx.Get("correlation_id"); exists && correlationID != nil {
			return fmt.Sprintf("%v", correlationID)
		}
		if requestID, exists := ginCtx.Get("request_id"); exists && requestID != nil {
			return fmt.Sprintf("%v", requestID)
		}
	}
	return ""
}

// StructuredLogger provides structured logging methods for handlers
type StructuredLogger struct {
	logger interfaces.Logger
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(logger interfaces.Logger) *StructuredLogger {
	return &StructuredLogger{logger: logger}
}

// Info logs an info message
func (s *StructuredLogger) Info(ctx context.Context, message string, fields map[string]interface{}) {
	entry := interfaces.ErrorLogEntry{
		Timestamp: time.Now(),
		RequestID: s.getRequestID(ctx),
		UserID:    s.getUserID(ctx),
		Level:     interfaces.LogLevelInfo,
		Message:   message,
		Context:   fields,
		Service:   "erp-api-gateway",
		Component: "handler",
	}

	go func() {
		logCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logger.LogError(logCtx, entry)
	}()
}

// Warn logs a warning message
func (s *StructuredLogger) Warn(ctx context.Context, message string, fields map[string]interface{}) {
	entry := interfaces.ErrorLogEntry{
		Timestamp: time.Now(),
		RequestID: s.getRequestID(ctx),
		UserID:    s.getUserID(ctx),
		Level:     interfaces.LogLevelWarn,
		Message:   message,
		Context:   fields,
		Service:   "erp-api-gateway",
		Component: "handler",
	}

	go func() {
		logCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logger.LogError(logCtx, entry)
	}()
}

// Error logs an error message
func (s *StructuredLogger) Error(ctx context.Context, message string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	if err != nil {
		fields["error"] = err.Error()
	}

	entry := interfaces.ErrorLogEntry{
		Timestamp: time.Now(),
		RequestID: s.getRequestID(ctx),
		UserID:    s.getUserID(ctx),
		Level:     interfaces.LogLevelError,
		Message:   message,
		Error:     err.Error(),
		Context:   fields,
		Service:   "erp-api-gateway",
		Component: "handler",
	}

	// Log errors synchronously to ensure they're captured
	logCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.logger.LogError(logCtx, entry)
}

// getRequestID extracts request ID from context
func (s *StructuredLogger) getRequestID(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if requestID, exists := ginCtx.Get("request_id"); exists && requestID != nil {
			return fmt.Sprintf("%v", requestID)
		}
	}
	return ""
}

// getUserID extracts user ID from context
func (s *StructuredLogger) getUserID(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if userID, exists := ginCtx.Get("user_id"); exists && userID != nil {
			return fmt.Sprintf("%v", userID)
		}
	}
	return ""
}