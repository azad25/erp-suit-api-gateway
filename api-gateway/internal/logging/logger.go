package logging

// Logger defines the interface for logging
type Logger interface {
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
}

// NoOpLogger is a logger that does nothing
type NoOpLogger struct{}

func (l *NoOpLogger) Info(msg string, fields map[string]interface{}) {}
func (l *NoOpLogger) Warn(msg string, fields map[string]interface{}) {}
func (l *NoOpLogger) Error(msg string, fields map[string]interface{}) {}

// NewNoOpLogger creates a new no-op logger
func NewNoOpLogger() Logger {
	return &NoOpLogger{}
}