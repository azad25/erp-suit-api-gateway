// internal/circuitbreaker/circuitbreaker.go
package circuitbreaker

import (
    "errors"
    "sync"
    "time"
)

// State represents the circuit breaker state
type State string

const (
    StateClosed   State = "closed"
    StateHalfOpen State = "half-open"
    StateOpen     State = "open"
)

// Counts holds circuit breaker metrics
type Counts struct {
    Requests             uint32
    TotalSuccesses       uint32
    TotalFailures        uint32
    ConsecutiveSuccesses uint32
    ConsecutiveFailures  uint32
}

// CircuitBreakerConfig defines circuit breaker configuration
type CircuitBreakerConfig struct {
    Name          string
    MaxFailures   uint32        // Changed from MaxRequests to match config.go
    Interval      time.Duration
    Timeout       time.Duration
    ReadyToTrip   func(counts Counts) bool
    OnStateChange func(name string, from State, to State)
}

// CircuitBreaker manages failure detection
type CircuitBreaker struct {
    config CircuitBreakerConfig
    mutex  sync.Mutex
    state  State
    counts Counts
}

// New creates a new CircuitBreaker
func New(config *CircuitBreakerConfig) *CircuitBreaker {
    return &CircuitBreaker{
        config: *config,
        state:  StateClosed,
    }
}

// Execute runs the operation with circuit breaker protection
func (cb *CircuitBreaker) Execute(op func() error) error {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()

    if cb.state == StateOpen {
        return ErrCircuitOpen
    }

    err := op()
    if err != nil {
        cb.counts.TotalFailures++
        cb.counts.ConsecutiveFailures++
        if cb.config.ReadyToTrip(cb.counts) {
            cb.state = StateOpen
            if cb.config.OnStateChange != nil {
                cb.config.OnStateChange(cb.config.Name, StateClosed, StateOpen)
            }
        }
        return err
    }

    cb.counts.TotalSuccesses++
    cb.counts.ConsecutiveSuccesses++
    return nil
}

// ErrCircuitOpen is returned when the circuit is open
var ErrCircuitOpen = errors.New("circuit breaker is open")