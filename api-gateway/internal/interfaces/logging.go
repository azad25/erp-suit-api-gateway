package interfaces

import (
	"context"
	"time"
)

// Logger defines the interface for structured logging
type Logger interface {
	LogRequest(ctx context.Context, entry RequestLogEntry) error
	LogError(ctx context.Context, entry ErrorLogEntry) error
	LogEvent(ctx context.Context, entry EventLogEntry) error
	LogMetric(ctx context.Context, entry MetricLogEntry) error
	Close() error
}

// RequestLogEntry represents a request log entry
type RequestLogEntry struct {
	Timestamp     time.Time         `json:"timestamp"`
	RequestID     string            `json:"request_id"`
	UserID        string            `json:"user_id,omitempty"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	StatusCode    int               `json:"status_code"`
	Duration      time.Duration     `json:"duration"`
	UserAgent     string            `json:"user_agent,omitempty"`
	RemoteIP      string            `json:"remote_ip"`
	RequestSize   int64             `json:"request_size"`
	ResponseSize  int64             `json:"response_size"`
	Headers       map[string]string `json:"headers,omitempty"`
	QueryParams   map[string]string `json:"query_params,omitempty"`
}

// ErrorLogEntry represents an error log entry
type ErrorLogEntry struct {
	Timestamp     time.Time         `json:"timestamp"`
	RequestID     string            `json:"request_id"`
	UserID        string            `json:"user_id,omitempty"`
	Level         string            `json:"level"`
	Message       string            `json:"message"`
	Error         string            `json:"error"`
	StackTrace    string            `json:"stack_trace,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty"`
	Service       string            `json:"service"`
	Component     string            `json:"component"`
}

// EventLogEntry represents an event log entry
type EventLogEntry struct {
	Timestamp     time.Time         `json:"timestamp"`
	EventID       string            `json:"event_id"`
	EventType     string            `json:"event_type"`
	UserID        string            `json:"user_id,omitempty"`
	CorrelationID string            `json:"correlation_id"`
	Source        string            `json:"source"`
	Data          map[string]interface{} `json:"data"`
	Success       bool              `json:"success"`
}

// MetricLogEntry represents a metric log entry
type MetricLogEntry struct {
	Timestamp   time.Time         `json:"timestamp"`
	MetricName  string            `json:"metric_name"`
	MetricType  string            `json:"metric_type"` // counter, gauge, histogram
	Value       float64           `json:"value"`
	Labels      map[string]string `json:"labels,omitempty"`
	Unit        string            `json:"unit,omitempty"`
}

// SimpleLogger defines a simple logging interface for internal services
type SimpleLogger interface {
	LogInfo(ctx context.Context, message string, fields map[string]interface{})
	LogWarning(ctx context.Context, message string, fields map[string]interface{})
	LogError(ctx context.Context, message string, fields map[string]interface{})
}

// LogLevel constants
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
	LogLevelFatal = "fatal"
)