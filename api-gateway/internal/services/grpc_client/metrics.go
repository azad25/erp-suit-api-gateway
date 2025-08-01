// service/grpc_client/metrics.go
package grpc_client

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics tracks gRPC client metrics
type Metrics struct {
	connectionMetrics     map[string]*ConnectionMetrics
	callMetrics          map[string]*CallMetrics
	circuitBreakerMetrics map[string]*CircuitBreakerMetrics
	mutex                sync.RWMutex

	// Prometheus metrics
	connTotal           *prometheus.CounterVec
	connActive          *prometheus.GaugeVec
	connErrors          *prometheus.CounterVec
	connDuration        *prometheus.HistogramVec
	grpcCallsTotal      *prometheus.CounterVec
	grpcCallsFailed     *prometheus.CounterVec
	grpcLatency         *prometheus.HistogramVec
	grpcErrorByType     *prometheus.CounterVec
	cbState             *prometheus.GaugeVec
	cbRequestsTotal     *prometheus.CounterVec
	cbRequestsRejected  *prometheus.CounterVec
	cbStateChangesTotal *prometheus.CounterVec
}

// ConnectionMetrics tracks connection-related metrics
type ConnectionMetrics struct {
	Service             string        `json:"service"`
	TotalConnections    int64         `json:"total_connections"`
	ActiveConnections   int64         `json:"active_connections"`
	FailedConnections   int64         `json:"failed_connections"`
	ConnectionErrors    int64         `json:"connection_errors"`
	AverageConnectTime  time.Duration `json:"average_connect_time"`
	LastConnectionTime  time.Time     `json:"last_connection_time"`
	LastConnectionError string        `json:"last_connection_error,omitempty"`
	totalConnectTime    time.Duration
	MinLatency          time.Duration `json:"min_latency"`
	MaxLatency          time.Duration `json:"max_latency"`
}

// CallMetrics tracks gRPC call metrics
type CallMetrics struct {
	Service           string            `json:"service"`
	TotalCalls        int64             `json:"total_calls"`
	SuccessfulCalls   int64             `json:"successful_calls"`
	FailedCalls       int64             `json:"failed_calls"`
	AverageLatency    time.Duration     `json:"average_latency"`
	MinLatency        time.Duration     `json:"min_latency"`
	MaxLatency        time.Duration     `json:"max_latency"`
	LastCallTime      time.Time         `json:"last_call_time"`
	LastCallError     string            `json:"last_call_error,omitempty"`
	totalLatency      time.Duration
	ErrorsByType      map[string]int64  `json:"errors_by_type"`
}

// CircuitBreakerMetrics tracks circuit breaker metrics
type CircuitBreakerMetrics struct {
	Service            string            `json:"service"`
	State              string            `json:"state"`
	TotalRequests      int64             `json:"total_requests"`
	SuccessfulRequests int64             `json:"successful_requests"`
	FailedRequests     int64             `json:"failed_requests"`
	RejectedRequests   int64             `json:"rejected_requests"`
	StateChanges       int64             `json:"state_changes"`
	LastStateChange    time.Time         `json:"last_state_change"`
	StateHistory       []StateChangeEvent `json:"state_history"`
}

// StateChangeEvent represents a circuit breaker state change
type StateChangeEvent struct {
	FromState string    `json:"from_state"`
	ToState   string    `json:"to_state"`
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason,omitempty"`
}

// NewMetrics creates a new metrics instance with Prometheus metrics
func NewMetrics() *Metrics {
	return NewMetricsWithRegistry(nil)
}

// NewMetricsWithRegistry creates a new metrics instance with a custom registry
func NewMetricsWithRegistry(registry prometheus.Registerer) *Metrics {
	m := &Metrics{
		connectionMetrics:     make(map[string]*ConnectionMetrics),
		callMetrics:          make(map[string]*CallMetrics),
		circuitBreakerMetrics: make(map[string]*CircuitBreakerMetrics),
	}

	// Use custom registry or default
	if registry == nil {
		registry = prometheus.DefaultRegisterer
	}

	// Initialize Prometheus metrics
	m.connTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_connections_total",
			Help: "Total number of gRPC connections attempted",
		},
		[]string{"service"},
	)
	m.connActive = promauto.With(registry).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "grpc_client_connections_active",
			Help: "Number of active gRPC connections",
		},
		[]string{"service"},
	)
	m.connErrors = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_connection_errors_total",
			Help: "Total number of gRPC connection errors",
		},
		[]string{"service"},
	)
	m.connDuration = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_client_connection_duration_seconds",
			Help:    "Duration of gRPC connection attempts in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"service"},
	)
	m.grpcCallsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_calls_total",
			Help: "Total number of gRPC calls",
		},
		[]string{"service"},
	)
	m.grpcCallsFailed = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_calls_failed_total",
			Help: "Total number of failed gRPC calls",
		},
		[]string{"service"},
	)
	m.grpcLatency = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_client_call_latency_seconds",
			Help:    "Latency of gRPC calls in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"service"},
	)
	m.grpcErrorByType = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_call_errors_total",
			Help: "Total number of gRPC call errors by type",
		},
		[]string{"service", "error_type"},
	)
	m.cbState = promauto.With(registry).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "grpc_client_circuit_breaker_state",
			Help: "Current state of circuit breaker (0=closed, 1=half-open, 2=open)",
		},
		[]string{"service"},
	)
	m.cbRequestsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_circuit_breaker_requests_total",
			Help: "Total number of circuit breaker requests",
		},
		[]string{"service", "status"},
	)
	m.cbRequestsRejected = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_circuit_breaker_rejected_total",
			Help: "Total number of rejected circuit breaker requests",
		},
		[]string{"service"},
	)
	m.cbStateChangesTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_client_circuit_breaker_state_changes_total",
			Help: "Total number of circuit breaker state changes",
		},
		[]string{"service"},
	)

	return m
}

// RecordConnectionSuccess records a successful connection
func (m *Metrics) RecordConnectionSuccess(service string, duration time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.connectionMetrics[service] == nil {
		m.connectionMetrics[service] = &ConnectionMetrics{
			Service:     service,
			MinLatency:  duration,
			MaxLatency:  duration,
		}
	}

	metrics := m.connectionMetrics[service]
	metrics.TotalConnections++
	metrics.ActiveConnections++
	metrics.LastConnectionTime = time.Now()
	metrics.totalConnectTime += duration

	// Calculate average
	if metrics.TotalConnections > 0 {
		metrics.AverageConnectTime = metrics.totalConnectTime / time.Duration(metrics.TotalConnections)
	}

	// Clear last error on success
	metrics.LastConnectionError = ""

	// Update Prometheus metrics
	m.connTotal.WithLabelValues(service).Inc()
	m.connActive.WithLabelValues(service).Inc()
	m.connDuration.WithLabelValues(service).Observe(duration.Seconds())
}

// RecordConnectionError records a connection error
func (m *Metrics) RecordConnectionError(service string, errorMsg string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.connectionMetrics[service] == nil {
		m.connectionMetrics[service] = &ConnectionMetrics{
			Service: service,
		}
	}

	metrics := m.connectionMetrics[service]
	metrics.FailedConnections++
	metrics.ConnectionErrors++
	metrics.LastConnectionError = errorMsg
	metrics.LastConnectionTime = time.Now()

	// Update Prometheus metrics
	m.connErrors.WithLabelValues(service).Inc()
}

// RecordConnectionClosed records a connection closure
func (m *Metrics) RecordConnectionClosed(service string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if metrics := m.connectionMetrics[service]; metrics != nil && metrics.ActiveConnections > 0 {
		metrics.ActiveConnections--
		m.connActive.WithLabelValues(service).Dec()
	}
}

// RecordCallSuccess records a successful gRPC call
func (m *Metrics) RecordCallSuccess(service string, duration time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.callMetrics[service] == nil {
		m.callMetrics[service] = &CallMetrics{
			Service:      service,
			MinLatency:   duration,
			MaxLatency:   duration,
			ErrorsByType: make(map[string]int64),
		}
	}

	metrics := m.callMetrics[service]
	metrics.TotalCalls++
	metrics.SuccessfulCalls++
	metrics.LastCallTime = time.Now()
	metrics.totalLatency += duration

	// Update min/max latency
	if duration < metrics.MinLatency {
		metrics.MinLatency = duration
	}
	if duration > metrics.MaxLatency {
		metrics.MaxLatency = duration
	}

	// Calculate average latency
	if metrics.TotalCalls > 0 {
		metrics.AverageLatency = metrics.totalLatency / time.Duration(metrics.TotalCalls)
	}

	// Clear last error on success
	metrics.LastCallError = ""

	// Update Prometheus metrics
	m.grpcCallsTotal.WithLabelValues(service).Inc()
	m.grpcLatency.WithLabelValues(service).Observe(duration.Seconds())
	m.cbRequestsTotal.WithLabelValues(service, "success").Inc()
}

// RecordCallError records a failed gRPC call
func (m *Metrics) RecordCallError(service string, errorMsg string, duration time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.callMetrics[service] == nil {
		m.callMetrics[service] = &CallMetrics{
			Service:      service,
			ErrorsByType: make(map[string]int64),
		}
	}

	metrics := m.callMetrics[service]
	metrics.TotalCalls++
	metrics.FailedCalls++
	metrics.LastCallTime = time.Now()
	metrics.LastCallError = errorMsg
	metrics.totalLatency += duration

	// Track error types
	errorType := m.categorizeError(errorMsg)
	metrics.ErrorsByType[errorType]++

	// Update latency stats (even for failed calls)
	if metrics.MinLatency == 0 || duration < metrics.MinLatency {
		metrics.MinLatency = duration
	}
	if duration > metrics.MaxLatency {
		metrics.MaxLatency = duration
	}

	// Calculate average latency
	if metrics.TotalCalls > 0 {
		metrics.AverageLatency = metrics.totalLatency / time.Duration(metrics.TotalCalls)
	}

	// Update Prometheus metrics
	m.grpcCallsTotal.WithLabelValues(service).Inc()
	m.grpcCallsFailed.WithLabelValues(service).Inc()
	m.grpcLatency.WithLabelValues(service).Observe(duration.Seconds())
	m.grpcErrorByType.WithLabelValues(service, errorType).Inc()
	m.cbRequestsTotal.WithLabelValues(service, "failed").Inc()
}

// categorizeError categorizes errors into types for metrics
func (m *Metrics) categorizeError(errorMsg string) string {
	errorMsg = strings.ToLower(errorMsg)
	switch {
	case contains(errorMsg, "timeout") || contains(errorMsg, "deadline"):
		return "timeout"
	case contains(errorMsg, "connection") || contains(errorMsg, "unavailable"):
		return "connection"
	case contains(errorMsg, "permission") || contains(errorMsg, "unauthorized"):
		return "authorization"
	case contains(errorMsg, "not found"):
		return "not_found"
	case contains(errorMsg, "invalid") || contains(errorMsg, "bad request"):
		return "validation"
	case contains(errorMsg, "rate limit"):
		return "rate_limit"
	case contains(errorMsg, "circuit breaker"):
		return "circuit_breaker"
	default:
		return "other"
	}
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// RecordCircuitBreakerStateChange records a circuit breaker state change
func (m *Metrics) RecordCircuitBreakerStateChange(service string, newState string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.circuitBreakerMetrics[service] == nil {
		m.circuitBreakerMetrics[service] = &CircuitBreakerMetrics{
			Service:      service,
			StateHistory: make([]StateChangeEvent, 0),
		}
	}

	metrics := m.circuitBreakerMetrics[service]
	oldState := metrics.State

	metrics.State = newState
	metrics.StateChanges++
	metrics.LastStateChange = time.Now()

	// Add to state history (keep last 10 changes)
	event := StateChangeEvent{
		FromState: oldState,
		ToState:   newState,
		Timestamp: time.Now(),
	}
	metrics.StateHistory = append(metrics.StateHistory, event)
	if len(metrics.StateHistory) > 10 {
		metrics.StateHistory = metrics.StateHistory[1:]
	}

	// Update Prometheus metrics
	var stateValue float64
	switch newState {
	case "closed":
		stateValue = 0
	case "half-open":
		stateValue = 1
	case "open":
		stateValue = 2
	}
	m.cbState.WithLabelValues(service).Set(stateValue)
	m.cbStateChangesTotal.WithLabelValues(service).Inc()
}

// RecordCircuitBreakerRequest records a circuit breaker request
func (m *Metrics) RecordCircuitBreakerRequest(service string, success bool, rejected bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.circuitBreakerMetrics[service] == nil {
		m.circuitBreakerMetrics[service] = &CircuitBreakerMetrics{
			Service:      service,
			StateHistory: make([]StateChangeEvent, 0),
		}
	}

	metrics := m.circuitBreakerMetrics[service]
	metrics.TotalRequests++

	if rejected {
		metrics.RejectedRequests++
		m.cbRequestsRejected.WithLabelValues(service).Inc()
	} else if success {
		metrics.SuccessfulRequests++
	} else {
		metrics.FailedRequests++
	}
}

// GetConnectionMetrics returns connection metrics for a service
func (m *Metrics) GetConnectionMetrics(service string) *ConnectionMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if metrics, exists := m.connectionMetrics[service]; exists {
		// Return a copy to avoid race conditions
		metricsCopy := *metrics
		return &metricsCopy
	}

	return &ConnectionMetrics{Service: service}
}

// GetCallMetrics returns call metrics for a service
func (m *Metrics) GetCallMetrics(service string) *CallMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if metrics, exists := m.callMetrics[service]; exists {
		// Return a copy to avoid race conditions
		metricsCopy := *metrics
		metricsCopy.ErrorsByType = make(map[string]int64)
		for k, v := range metrics.ErrorsByType {
			metricsCopy.ErrorsByType[k] = v
		}
		return &metricsCopy
	}

	return &CallMetrics{Service: service}
}

// GetCircuitBreakerMetrics returns circuit breaker metrics for a service
func (m *Metrics) GetCircuitBreakerMetrics(service string) *CircuitBreakerMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if metrics, exists := m.circuitBreakerMetrics[service]; exists {
		// Return a copy to avoid race conditions
		metricsCopy := *metrics
		metricsCopy.StateHistory = make([]StateChangeEvent, len(metrics.StateHistory))
		copy(metricsCopy.StateHistory, metrics.StateHistory)
		return &metricsCopy
	}

	return &CircuitBreakerMetrics{Service: service}
}