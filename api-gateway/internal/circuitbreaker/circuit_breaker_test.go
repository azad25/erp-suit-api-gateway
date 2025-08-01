package circuitbreaker

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewCircuitBreaker(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:         "test-breaker",
		MaxFailures:  5,
		Interval:     10 * time.Second,
		Timeout:      60 * time.Second,
		ReadyToTrip:  func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 3
		},
	}

	cb := New(config)
	
	assert.NotNil(t, cb)
	assert.Equal(t, StateClosed, cb.state)
}

func TestCircuitBreaker_Execute_Success(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:         "test-success",
		MaxFailures:  5,
		Interval:     10 * time.Second,
		Timeout:      60 * time.Second,
		ReadyToTrip:  func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 3
		},
	}

	cb := New(config)
	
	err := cb.Execute(func() error {
		return nil
	})
	
	assert.NoError(t, err)
	assert.Equal(t, StateClosed, cb.state)
	assert.Equal(t, uint32(1), cb.counts.TotalSuccesses)
}

func TestCircuitBreaker_Execute_Failure(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:         "test-failure",
		MaxFailures:  5,
		Interval:     10 * time.Second,
		Timeout:      60 * time.Second,
		ReadyToTrip:  func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 2 // Trip after 2 consecutive failures
		},
	}

	cb := New(config)
	
	// First failure
	err := cb.Execute(func() error {
		return errors.New("test error")
	})
	
	assert.Error(t, err)
	assert.Equal(t, StateClosed, cb.state)
	assert.Equal(t, uint32(1), cb.counts.ConsecutiveFailures)
	
	// Second failure - should trip the breaker
	err = cb.Execute(func() error {
		return errors.New("test error")
	})
	
	assert.Error(t, err)
	assert.Equal(t, StateOpen, cb.state)
	assert.Equal(t, uint32(2), cb.counts.ConsecutiveFailures)
}

func TestCircuitBreaker_Execute_Open(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:         "test-open",
		MaxFailures:  5,
		Interval:     10 * time.Second,
		Timeout:      60 * time.Second,
		ReadyToTrip:  func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 1
		},
	}

	cb := New(config)
	
	// Cause a failure to open the circuit
	err := cb.Execute(func() error {
		return errors.New("test error")
	})
	
	assert.Error(t, err)
	assert.Equal(t, StateOpen, cb.state)
	
	// Next call should return circuit open error
	err = cb.Execute(func() error {
		return nil
	})
	
	assert.Equal(t, ErrCircuitOpen, err)
}

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	stateChanges := make([]string, 0)
	
	config := &CircuitBreakerConfig{
		Name:         "test-transitions",
		MaxFailures:  5,
		Interval:     10 * time.Second,
		Timeout:      60 * time.Second,
		ReadyToTrip:  func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 1
		},
		OnStateChange: func(name string, from State, to State) {
			stateChanges = append(stateChanges, string(from)+"->"+string(to))
		},
	}

	cb := New(config)
	
	// Cause a failure to open the circuit
	err := cb.Execute(func() error {
		return errors.New("test error")
	})
	
	assert.Error(t, err)
	assert.Equal(t, StateOpen, cb.state)
	assert.Len(t, stateChanges, 1)
	assert.Equal(t, "closed->open", stateChanges[0])
}