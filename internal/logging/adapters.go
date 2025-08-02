package logging

import (
	"context"
	"fmt"
	"time"

	"erp-api-gateway/internal/interfaces"
	"github.com/gin-gonic/gin"
)

const (
	defaultLogTimeout = 5 * time.Second
)

// SimpleLoggerAdapter adapts the full Logger interface to SimpleLogger
type SimpleLoggerAdapter struct {
	logger interfaces.Logger
}

// NewSimpleLogger creates a new SimpleLogger adapter
func NewSimpleLogger(logger interfaces.Logger) interfaces.SimpleLogger {
	return &SimpleLoggerAdapter{
		logger: logger,
	}
}

// LogInfo logs an info message
func (s *SimpleLoggerAdapter) LogInfo(ctx context.Context, message string, fields map[string]interface{}) {
	entry := interfaces.ErrorLogEntry{
		Timestamp: getCurrentTime(),
		RequestID: getRequestIDFromContext(ctx),
		UserID:    getUserIDFromContext(ctx),
		Level:     interfaces.LogLevelInfo,
		Message:   message,
		Context:   fields,
		Service:   "erp-api-gateway",
		Component: "service",
	}

	// Log asynchronously to avoid blocking
	go func() {
		logCtx, cancel := context.WithTimeout(context.Background(), defaultLogTimeout)
		defer cancel()
		s.logger.LogError(logCtx, entry)
	}()
}

// LogWarning logs a warning message
func (s *SimpleLoggerAdapter) LogWarning(ctx context.Context, message string, fields map[string]interface{}) {
	entry := interfaces.ErrorLogEntry{
		Timestamp: getCurrentTime(),
		RequestID: getRequestIDFromContext(ctx),
		UserID:    getUserIDFromContext(ctx),
		Level:     interfaces.LogLevelWarn,
		Message:   message,
		Context:   fields,
		Service:   "erp-api-gateway",
		Component: "service",
	}

	// Log asynchronously to avoid blocking
	go func() {
		logCtx, cancel := context.WithTimeout(context.Background(), defaultLogTimeout)
		defer cancel()
		s.logger.LogError(logCtx, entry)
	}()
}

// LogError logs an error message
func (s *SimpleLoggerAdapter) LogError(ctx context.Context, message string, fields map[string]interface{}) {
	entry := interfaces.ErrorLogEntry{
		Timestamp: getCurrentTime(),
		RequestID: getRequestIDFromContext(ctx),
		UserID:    getUserIDFromContext(ctx),
		Level:     interfaces.LogLevelError,
		Message:   message,
		Context:   fields,
		Service:   "erp-api-gateway",
		Component: "service",
	}

	// Log synchronously for errors to ensure they're captured
	logCtx, cancel := context.WithTimeout(context.Background(), defaultLogTimeout)
	defer cancel()
	s.logger.LogError(logCtx, entry)
}

// LoggerAdapter adapts SimpleLogger to the full Logger interface
type LoggerAdapter struct {
	simpleLogger interfaces.SimpleLogger
}

// NewLogger creates a new Logger adapter from SimpleLogger
func NewLogger(simpleLogger interfaces.SimpleLogger) interfaces.Logger {
	return &LoggerAdapter{
		simpleLogger: simpleLogger,
	}
}

// LogRequest logs a request entry (simplified implementation)
func (l *LoggerAdapter) LogRequest(ctx context.Context, entry interfaces.RequestLogEntry) error {
	fields := map[string]interface{}{
		"method":        entry.Method,
		"path":          entry.Path,
		"status_code":   entry.StatusCode,
		"duration":      entry.Duration,
		"user_agent":    entry.UserAgent,
		"remote_ip":     entry.RemoteIP,
		"request_size":  entry.RequestSize,
		"response_size": entry.ResponseSize,
	}

	message := "HTTP Request"
	l.simpleLogger.LogInfo(ctx, message, fields)
	return nil
}

// LogError logs an error entry
func (l *LoggerAdapter) LogError(ctx context.Context, entry interfaces.ErrorLogEntry) error {
	fields := map[string]interface{}{
		"level":      entry.Level,
		"error":      entry.Error,
		"service":    entry.Service,
		"component":  entry.Component,
		"context":    entry.Context,
	}

	l.simpleLogger.LogError(ctx, entry.Message, fields)
	return nil
}

// LogEvent logs an event entry
func (l *LoggerAdapter) LogEvent(ctx context.Context, entry interfaces.EventLogEntry) error {
	fields := map[string]interface{}{
		"event_id":       entry.EventID,
		"event_type":     entry.EventType,
		"correlation_id": entry.CorrelationID,
		"source":         entry.Source,
		"data":           entry.Data,
		"success":        entry.Success,
	}

	message := "Business Event"
	l.simpleLogger.LogInfo(ctx, message, fields)
	return nil
}

// LogMetric logs a metric entry
func (l *LoggerAdapter) LogMetric(ctx context.Context, entry interfaces.MetricLogEntry) error {
	fields := map[string]interface{}{
		"metric_name": entry.MetricName,
		"metric_type": entry.MetricType,
		"value":       entry.Value,
		"labels":      entry.Labels,
		"unit":        entry.Unit,
	}

	message := "Metric"
	l.simpleLogger.LogInfo(ctx, message, fields)
	return nil
}

// Close closes the logger (no-op for adapter)
func (l *LoggerAdapter) Close() error {
	return nil
}

// Helper functions

// getCurrentTime returns the current time
func getCurrentTime() time.Time {
	return time.Now()
}

// getRequestIDFromContext extracts request ID from context
func getRequestIDFromContext(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if requestID, exists := ginCtx.Get("request_id"); exists && requestID != nil {
			return fmt.Sprintf("%v", requestID)
		}
	}
	return ""
}

// getUserIDFromContext extracts user ID from context
func getUserIDFromContext(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if userID, exists := ginCtx.Get("user_id"); exists && userID != nil {
			return fmt.Sprintf("%v", userID)
		}
	}
	return ""
}