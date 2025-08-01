// internal/services/grpc_client/grpc_client_test.go
package grpc_client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"erp-api-gateway/internal/config"
)

// MockLogger is a mock for the logging.Logger interface
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Info(msg string, fields map[string]interface{}) {
	m.Called(msg, fields)
}

func (m *MockLogger) Warn(msg string, fields map[string]interface{}) {
	m.Called(msg, fields)
}

func (m *MockLogger) Error(msg string, fields map[string]interface{}) {
	m.Called(msg, fields)
}

func TestGRPCClientCreation(t *testing.T) {
	// Mock dependencies
	logger := &MockLogger{}
	logger.On("Info", mock.Anything, mock.Anything).Return()
	logger.On("Warn", mock.Anything, mock.Anything).Return()
	logger.On("Error", mock.Anything, mock.Anything).Return()

	cfg := &config.GRPCConfig{
		AuthServiceAddress:        "localhost:50051",
		CRMServiceAddress:         "localhost:50052",
		HRMServiceAddress:         "localhost:50053",
		FinanceServiceAddress:     "localhost:50054",
		MaxRetries:                3,
		RetryInitialInterval:      time.Millisecond * 100,
		RetryMaxInterval:          time.Second,
		RetryMultiplier:           2.0,
		RetryRandomFactor:         0.5,
		MaxConnections:            10,
		ConnectTimeout:            time.Second * 5,
		CircuitBreakerMaxRequests: 5,
		CircuitBreakerInterval:    time.Second * 30,
		CircuitBreakerTimeout:     time.Second * 60,
		EnableHealthCheck:         true,
		HealthCheckInterval:       time.Second * 10,
	}

	t.Run("NewGRPCClient", func(t *testing.T) {
		client, err := NewGRPCClient(cfg, logger)
		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.NotNil(t, client.connManager)
		assert.NotNil(t, client.retryConfig)
		assert.NotNil(t, client.errorHandler)
		assert.NotNil(t, client.metrics)
		assert.Len(t, client.circuitBreakers, 4) // auth, crm, hrm, finance

		// Clean up
		err = client.Close()
		assert.NoError(t, err)
	})

	t.Run("ServiceDiscovery", func(t *testing.T) {
		client, err := NewGRPCClient(cfg, logger)
		assert.NoError(t, err)
		assert.NotNil(t, client.serviceDiscovery)

		// Test static service discovery
		addr, err := client.serviceDiscovery.GetServiceAddress("auth")
		assert.NoError(t, err)
		assert.Equal(t, "localhost:50051", addr)

		// Clean up
		err = client.Close()
		assert.NoError(t, err)
	})

	t.Run("CircuitBreakerInitialization", func(t *testing.T) {
		client, err := NewGRPCClient(cfg, logger)
		assert.NoError(t, err)

		// Check that circuit breakers are initialized for all services
		services := []string{"auth", "crm", "hrm", "finance"}
		for _, service := range services {
			cb := client.getCircuitBreaker(service)
			assert.NotNil(t, cb)
		}

		// Clean up
		err = client.Close()
		assert.NoError(t, err)
	})

	t.Run("MetricsInitialization", func(t *testing.T) {
		client, err := NewGRPCClient(cfg, logger)
		assert.NoError(t, err)

		metrics := client.GetMetrics()
		assert.NotNil(t, metrics)

		// Test metrics recording
		metrics.RecordConnectionSuccess("auth", time.Millisecond*100)
		connMetrics := metrics.GetConnectionMetrics("auth")
		assert.Equal(t, int64(1), connMetrics.TotalConnections)

		// Clean up
		err = client.Close()
		assert.NoError(t, err)
	})
}

func TestRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()
	assert.NotNil(t, config)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, config.InitialInterval)
	assert.Equal(t, 30*time.Second, config.MaxInterval)
	assert.Equal(t, 2.0, config.Multiplier)
	assert.Equal(t, 0.1, config.RandomFactor)

	t.Run("CalculateBackoff", func(t *testing.T) {
		// Test first attempt (should be initial interval)
		backoff := config.calculateBackoff(0)
		// Allow for some jitter variation
		assert.True(t, backoff >= config.InitialInterval/2)
		assert.True(t, backoff <= config.InitialInterval*2)

		// Test second attempt (should be roughly 2x initial interval)
		backoff = config.calculateBackoff(1)
		assert.True(t, backoff >= config.InitialInterval)
		assert.True(t, backoff <= config.MaxInterval)
	})
}

func TestConnectionManager(t *testing.T) {
	logger := &MockLogger{}
	logger.On("Info", mock.Anything, mock.Anything).Return()
	logger.On("Warn", mock.Anything, mock.Anything).Return()
	logger.On("Error", mock.Anything, mock.Anything).Return()

	config := DefaultConnectionConfig()
	healthChecker := NewHealthChecker(logger)
	connManager := NewConnectionManager(config, healthChecker)

	assert.NotNil(t, connManager)

	t.Run("GetConnectionStats", func(t *testing.T) {
		stats := connManager.GetConnectionStats()
		assert.NotNil(t, stats)
		assert.Equal(t, 0, len(stats))
	})

	// Clean up
	err := connManager.Close()
	assert.NoError(t, err)
}