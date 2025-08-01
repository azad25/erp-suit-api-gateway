// service/grpc_client/retry.go
package grpc_client

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxRetries      int           `yaml:"max_retries"`
	InitialInterval time.Duration `yaml:"initial_interval"`
	MaxInterval     time.Duration `yaml:"max_interval"`
	Multiplier      float64       `yaml:"multiplier"`
	RandomFactor    float64       `yaml:"random_factor"`
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:      3,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		RandomFactor:    0.1,
	}
}

// ExecuteWithRetry executes a function with exponential backoff retry logic
func (rc *RetryConfig) ExecuteWithRetry(ctx context.Context, fn func() error) error {
	var lastErr error
	
	for attempt := 0; attempt <= rc.MaxRetries; attempt++ {
		// Execute the function
		err := fn()
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Check if error is non-retryable
		if nonRetryable, ok := err.(*NonRetryableError); ok {
			return nonRetryable.Err
		}
		
		// Check if context is cancelled or deadline exceeded
		if ctx.Err() != nil {
			return fmt.Errorf("context cancelled during retry: %w", ctx.Err())
		}
		
		// Don't sleep after the last attempt
		if attempt == rc.MaxRetries {
			break
		}
		
		// Calculate backoff delay
		delay := rc.calculateBackoff(attempt)
		
		// Wait for the delay or context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during backoff: %w", ctx.Err())
		case <-time.After(delay):
			continue
		}
	}
	
	return fmt.Errorf("max retries (%d) exceeded, last error: %w", rc.MaxRetries, lastErr)
}

// calculateBackoff calculates the backoff delay for a given attempt
func (rc *RetryConfig) calculateBackoff(attempt int) time.Duration {
	// Calculate exponential backoff
	backoff := float64(rc.InitialInterval) * math.Pow(rc.Multiplier, float64(attempt))
	
	// Apply jitter to avoid thundering herd
	if rc.RandomFactor > 0 {
		jitter := backoff * rc.RandomFactor * (rand.Float64()*2 - 1)
		backoff += jitter
	}
	
	// Ensure backoff doesn't exceed max interval
	if backoff > float64(rc.MaxInterval) {
		backoff = float64(rc.MaxInterval)
	}
	
	// Ensure backoff is not negative
	if backoff < 0 {
		backoff = float64(rc.InitialInterval)
	}
	
	return time.Duration(backoff)
}

// RetryableFunc represents a function that can be retried
type RetryableFunc func() error

// RetryWithBackoff is a convenience function for executing with retry
func RetryWithBackoff(ctx context.Context, config *RetryConfig, fn RetryableFunc) error {
	if config == nil {
		config = DefaultRetryConfig()
	}
	
	return config.ExecuteWithRetry(ctx, fn)
}

// IsRetryableGRPCError checks if a gRPC error should be retried
func IsRetryableGRPCError(err error) bool {
	if err == nil {
		return false
	}
	
	// Add specific gRPC error checking logic here
	// This is a placeholder implementation
	errorString := err.Error()
	
	// Common retryable error patterns
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"unavailable",
		"deadline exceeded",
		"internal error",
		"resource exhausted",
	}
	
	for _, pattern := range retryablePatterns {
		if contains(errorString, pattern) {
			return true
		}
	}
	
	return false
}



// RetryStats holds statistics about retry operations
type RetryStats struct {
	TotalAttempts    int           `json:"total_attempts"`
	SuccessfulCalls  int           `json:"successful_calls"`
	FailedCalls      int           `json:"failed_calls"`
	AverageRetries   float64       `json:"average_retries"`
	TotalRetryTime   time.Duration `json:"total_retry_time"`
	LastRetryTime    time.Time     `json:"last_retry_time"`
}

// RetryMetrics tracks retry statistics
type RetryMetrics struct {
	stats map[string]*RetryStats
}

// NewRetryMetrics creates a new retry metrics tracker
func NewRetryMetrics() *RetryMetrics {
	return &RetryMetrics{
		stats: make(map[string]*RetryStats),
	}
}

// RecordAttempt records a retry attempt
func (rm *RetryMetrics) RecordAttempt(service string, attempts int, success bool, duration time.Duration) {
	if rm.stats[service] == nil {
		rm.stats[service] = &RetryStats{}
	}
	
	stats := rm.stats[service]
	stats.TotalAttempts += attempts
	stats.TotalRetryTime += duration
	stats.LastRetryTime = time.Now()
	
	if success {
		stats.SuccessfulCalls++
	} else {
		stats.FailedCalls++
	}
	
	// Calculate average retries
	totalCalls := stats.SuccessfulCalls + stats.FailedCalls
	if totalCalls > 0 {
		stats.AverageRetries = float64(stats.TotalAttempts) / float64(totalCalls)
	}
}

// GetStats returns retry statistics for a service
func (rm *RetryMetrics) GetStats(service string) *RetryStats {
	if stats, exists := rm.stats[service]; exists {
		// Return a copy to avoid race conditions
		statsCopy := *stats
		return &statsCopy
	}
	return &RetryStats{}
}

// GetAllStats returns retry statistics for all services
func (rm *RetryMetrics) GetAllStats() map[string]*RetryStats {
	result := make(map[string]*RetryStats)
	for service, stats := range rm.stats {
		// Return copies to avoid race conditions
		statsCopy := *stats
		result[service] = &statsCopy
	}
	return result
}

// NonRetryableError represents an error that should not be retried
type NonRetryableError struct {
	Err error
}

func (e *NonRetryableError) Error() string {
	return e.Err.Error()
}

// NewNonRetryableError creates a new non-retryable error
func NewNonRetryableError(err error) *NonRetryableError {
	return &NonRetryableError{Err: err}
}