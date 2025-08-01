package config

import (
	"time"
)

// CircuitBreakerConfig holds configuration for circuit breakers
type CircuitBreakerConfig struct {
	// Global settings
	Enabled bool `yaml:"enabled" json:"enabled"`
	
	// Default settings for all services
	Default CircuitBreakerSettings `yaml:"default" json:"default"`
	
	// Per-service settings (overrides default)
	Services map[string]CircuitBreakerSettings `yaml:"services" json:"services"`
}

// CircuitBreakerSettings holds individual circuit breaker settings
type CircuitBreakerSettings struct {
	// MaxRequests is the maximum number of requests allowed to pass through
	// when the CircuitBreaker is half-open
	MaxRequests uint32 `yaml:"max_requests" json:"max_requests"`
	
	// Interval is the cyclic period of the closed state for the CircuitBreaker
	// to clear the internal Counts
	Interval time.Duration `yaml:"interval" json:"interval"`
	
	// Timeout is the period of the open state, after which the state becomes half-open
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	
	// ReadyToTrip is the number of consecutive failures that will trip the breaker
	ReadyToTrip uint32 `yaml:"ready_to_trip" json:"ready_to_trip"`
}

// GetSettingsForService returns circuit breaker settings for a specific service
func (c *CircuitBreakerConfig) GetSettingsForService(serviceName string) CircuitBreakerSettings {
	if settings, exists := c.Services[serviceName]; exists {
		// Merge with defaults for any zero values
		return c.mergeWithDefaults(settings)
	}
	return c.Default
}

// mergeWithDefaults fills in zero values with defaults
func (c *CircuitBreakerConfig) mergeWithDefaults(settings CircuitBreakerSettings) CircuitBreakerSettings {
	if settings.MaxRequests == 0 {
		settings.MaxRequests = c.Default.MaxRequests
	}
	if settings.Interval == 0 {
		settings.Interval = c.Default.Interval
	}
	if settings.Timeout == 0 {
		settings.Timeout = c.Default.Timeout
	}
	if settings.ReadyToTrip == 0 {
		settings.ReadyToTrip = c.Default.ReadyToTrip
	}
	return settings
}

// DefaultCircuitBreakerConfig returns a default circuit breaker configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Enabled: true,
		Default: CircuitBreakerSettings{
			MaxRequests: 5,
			Interval:    30 * time.Second,
			Timeout:     60 * time.Second,
			ReadyToTrip: 3,
		},
		Services: map[string]CircuitBreakerSettings{
			"auth": {
				MaxRequests: 10,
				Interval:    30 * time.Second,
				Timeout:     30 * time.Second,
				ReadyToTrip: 5,
			},
			"crm": {
				MaxRequests: 5,
				Interval:    60 * time.Second,
				Timeout:     60 * time.Second,
				ReadyToTrip: 3,
			},
			"hrm": {
				MaxRequests: 5,
				Interval:    60 * time.Second,
				Timeout:     60 * time.Second,
				ReadyToTrip: 3,
			},
			"finance": {
				MaxRequests: 3,
				Interval:    120 * time.Second,
				Timeout:     90 * time.Second,
				ReadyToTrip: 2,
			},
		},
	}
}
