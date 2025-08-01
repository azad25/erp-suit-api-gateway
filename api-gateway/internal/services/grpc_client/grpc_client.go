// service/grpc_client/grpc_client.go
package grpc_client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"erp-api-gateway/internal/circuitbreaker"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	authpb "erp-api-gateway/proto/gen/auth"
	crmpb "erp-api-gateway/proto/gen/crm"
	hrmpb "erp-api-gateway/proto/gen/hrm"
	financepb "erp-api-gateway/proto/gen/finance"
)

// GRPCClient manages connections and communication with backend gRPC services
type GRPCClient struct {
	config           *config.GRPCConfig
	logger           logging.Logger
	connManager      *ConnectionManager
	circuitBreakers  map[string]*circuitbreaker.CircuitBreaker
	retryConfig      *RetryConfig
	errorHandler     *ErrorHandler
	serviceDiscovery ServiceDiscovery
	metrics          *Metrics
	mutex            sync.RWMutex
}

// NewGRPCClient creates a new gRPC client
func NewGRPCClient(cfg *config.GRPCConfig, logger logging.Logger) (*GRPCClient, error) {
	// Initialize service discovery
	var serviceDiscovery ServiceDiscovery
	if cfg.ConsulAddress != "" {
		var err error
		serviceDiscovery, err = NewConsulServiceDiscovery(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize service discovery: %w", err)
		}
	} else {
		// Fallback to static endpoints if Consul is not configured
		serviceDiscovery = &StaticServiceDiscovery{
			Endpoints: ServiceEndpoints{
				AuthService:    cfg.AuthServiceAddress,
				CRMService:     cfg.CRMServiceAddress,
				HRMService:     cfg.HRMServiceAddress,
				FinanceService: cfg.FinanceServiceAddress,
			},
		}
	}

	// Initialize connection manager
	connConfig := &ConnectionConfig{
		MaxIdleTime:         cfg.MaxIdleTime,
		MaxConnectionAge:    cfg.MaxConnectionAge,
		KeepAliveTime:       cfg.KeepAliveTime,
		KeepAliveTimeout:    cfg.KeepAliveTimeout,
		MaxConnections:      cfg.MaxConnections,
		ConnectTimeout:      cfg.ConnectTimeout,
		EnableHealthCheck:   cfg.EnableHealthCheck,
		HealthCheckInterval: cfg.HealthCheckInterval,
	}

	healthChecker := NewHealthChecker(logger)
	connManager := NewConnectionManager(connConfig, healthChecker)

	// Initialize retry configuration
	retryConfig := &RetryConfig{
		MaxRetries:      cfg.MaxRetries,
		InitialInterval: cfg.RetryInitialInterval,
		MaxInterval:     cfg.RetryMaxInterval,
		Multiplier:      cfg.RetryMultiplier,
		RandomFactor:    cfg.RetryRandomFactor,
	}

	// Initialize error handler
	errorHandler := NewErrorHandler(logger)

	// Initialize metrics with a new registry to avoid conflicts in tests
	registry := prometheus.NewRegistry()
	metrics := NewMetricsWithRegistry(registry)

	client := &GRPCClient{
		config:           cfg,
		logger:           logger,
		connManager:      connManager,
		circuitBreakers:  make(map[string]*circuitbreaker.CircuitBreaker),
		retryConfig:      retryConfig,
		errorHandler:     errorHandler,
		serviceDiscovery: serviceDiscovery,
		metrics:          metrics,
	}

	// Initialize circuit breakers for each service
	client.initializeCircuitBreakers()

	// Start watching services if Consul is enabled
	if _, ok := serviceDiscovery.(*ConsulServiceDiscovery); ok {
		go client.watchServices()
	}

	return client, nil
}

// StaticServiceDiscovery provides static service endpoints
type StaticServiceDiscovery struct {
	Endpoints ServiceEndpoints
}

func (s *StaticServiceDiscovery) GetServiceAddress(serviceName string) (string, error) {
	switch serviceName {
	case "auth":
		return s.Endpoints.AuthService, nil
	case "crm":
		return s.Endpoints.CRMService, nil
	case "hrm":
		return s.Endpoints.HRMService, nil
	case "finance":
		return s.Endpoints.FinanceService, nil
	default:
		return "", fmt.Errorf("unknown service: %s", serviceName)
	}
}

func (s *StaticServiceDiscovery) WatchService(_ string, _ chan<- string) {
	// No-op for static discovery
}

func (s *StaticServiceDiscovery) Close() error {
	return nil
}

// watchServices starts watching all services for address updates
func (c *GRPCClient) watchServices() {
	services := []struct {
		name    string
		defaultAddr string
	}{
		{"auth", c.config.AuthServiceAddress},
		{"crm", c.config.CRMServiceAddress},
		{"hrm", c.config.HRMServiceAddress},
		{"finance", c.config.FinanceServiceAddress},
	}

	for _, svc := range services {
		updateChan := make(chan string)
		c.config.SetServiceAddress(svc.name, svc.defaultAddr) // Initialize with default
		go c.serviceDiscovery.WatchService(svc.name, updateChan)
		go func(serviceName string) {
			for addr := range updateChan {
				c.config.SetServiceAddress(serviceName, addr)
				c.logger.Info("Updated service address",
					map[string]interface{}{
						"service": serviceName,
						"address": addr,
					})
			}
		}(svc.name)
	}
}



// AuthService returns an Auth service client
func (c *GRPCClient) AuthService(ctx context.Context) (authpb.AuthServiceClient, error) {
	conn, err := c.getServiceConnection(ctx, "auth", c.config.AuthServiceAddress)
	if err != nil {
		return nil, err
	}
	return authpb.NewAuthServiceClient(conn), nil
}

// CRMService returns a CRM service client
func (c *GRPCClient) CRMService(ctx context.Context) (crmpb.CRMServiceClient, error) {
	conn, err := c.getServiceConnection(ctx, "crm", c.config.CRMServiceAddress)
	if err != nil {
		return nil, err
	}
	return crmpb.NewCRMServiceClient(conn), nil
}

// HRMService returns an HRM service client
func (c *GRPCClient) HRMService(ctx context.Context) (hrmpb.HRMServiceClient, error) {
	conn, err := c.getServiceConnection(ctx, "hrm", c.config.HRMServiceAddress)
	if err != nil {
		return nil, err
	}
	return hrmpb.NewHRMServiceClient(conn), nil
}

// FinanceService returns a Finance service client
func (c *GRPCClient) FinanceService(ctx context.Context) (financepb.FinanceServiceClient, error) {
	conn, err := c.getServiceConnection(ctx, "finance", c.config.FinanceServiceAddress)
	if err != nil {
		return nil, err
	}
	return financepb.NewFinanceServiceClient(conn), nil
}
// getServiceConnection gets a connection for a service with circuit breaker protection
func (c *GRPCClient) getServiceConnection(ctx context.Context, serviceName, address string) (*grpc.ClientConn, error) {
	start := time.Now()
	
	// Get circuit breaker for this service
	cb := c.getCircuitBreaker(serviceName)
	
	var conn *grpc.ClientConn
	var err error
	
	// Execute with circuit breaker protection
	cbErr := cb.Execute(func() error {
		conn, err = c.connManager.GetConnection(ctx, address)
		return err
	})
	
	duration := time.Since(start)
	
	if cbErr != nil {
		c.metrics.RecordConnectionError(serviceName, cbErr.Error())
		return nil, cbErr
	}
	
	if err != nil {
		c.metrics.RecordConnectionError(serviceName, err.Error())
		return nil, err
	}
	
	c.metrics.RecordConnectionSuccess(serviceName, duration)
	return conn, nil
}

// getCircuitBreaker gets or creates a circuit breaker for a service
func (c *GRPCClient) getCircuitBreaker(serviceName string) *circuitbreaker.CircuitBreaker {
	c.mutex.RLock()
	if cb, exists := c.circuitBreakers[serviceName]; exists {
		c.mutex.RUnlock()
		return cb
	}
	c.mutex.RUnlock()
	
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if cb, exists := c.circuitBreakers[serviceName]; exists {
		return cb
	}
	
	// Create new circuit breaker
	cbConfig := &circuitbreaker.CircuitBreakerConfig{
		Name:        serviceName,
		MaxFailures: c.config.CircuitBreakerMaxRequests,
		Interval:    c.config.CircuitBreakerInterval,
		Timeout:     c.config.CircuitBreakerTimeout,
		ReadyToTrip: func(counts circuitbreaker.Counts) bool {
			return counts.ConsecutiveFailures >= c.config.CircuitBreakerMaxRequests
		},
		OnStateChange: c.onCircuitBreakerStateChange,
	}
	
	cb := circuitbreaker.New(cbConfig)
	c.circuitBreakers[serviceName] = cb
	return cb
}

// initializeCircuitBreakers initializes circuit breakers for all services
func (c *GRPCClient) initializeCircuitBreakers() {
	services := []string{"auth", "crm", "hrm", "finance"}
	for _, service := range services {
		c.getCircuitBreaker(service)
	}
}

// onCircuitBreakerStateChange handles circuit breaker state changes
func (c *GRPCClient) onCircuitBreakerStateChange(name string, from, to circuitbreaker.State) {
	c.logger.Warn("Circuit breaker state changed",
		map[string]interface{}{
			"service":    name,
			"from_state": string(from),
			"to_state":   string(to),
		})
	
	c.metrics.RecordCircuitBreakerStateChange(name, string(to))
}

// CallWithRetry executes a gRPC call with retry logic
func (c *GRPCClient) CallWithRetry(ctx context.Context, serviceName string, fn func() error) error {
	start := time.Now()
	
	err := c.retryConfig.ExecuteWithRetry(ctx, func() error {
		return fn()
	})
	
	duration := time.Since(start)
	
	if err != nil {
		c.logger.Warn("gRPC call failed, will retry",
			map[string]interface{}{
				"service": serviceName,
				"error":   err.Error(),
				"duration": duration.String(),
			})
		c.metrics.RecordCallError(serviceName, err.Error(), duration)
		return err
	}
	
	c.metrics.RecordCallSuccess(serviceName, duration)
	return nil
}

// HealthCheck performs health checks on all services
func (c *GRPCClient) HealthCheck(ctx context.Context) map[string]bool {
	results := make(map[string]bool)
	services := []struct {
		name    string
		address string
	}{
		{"auth", c.config.AuthServiceAddress},
		{"crm", c.config.CRMServiceAddress},
		{"hrm", c.config.HRMServiceAddress},
		{"finance", c.config.FinanceServiceAddress},
	}
	
	for _, svc := range services {
		conn, err := c.connManager.GetConnection(ctx, svc.address)
		if err != nil {
			results[svc.name] = false
			continue
		}
		
		healthy := c.connManager.healthCheck.CheckHealth(ctx, conn, svc.address)
		results[svc.name] = healthy
	}
	
	return results
}

// Close closes the gRPC client and all connections
func (c *GRPCClient) Close() error {
	var errs []error
	
	// Close service discovery
	if err := c.serviceDiscovery.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close service discovery: %w", err))
	}
	
	// Close connection manager
	if err := c.connManager.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close connection manager: %w", err))
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("errors closing gRPC client: %v", errs)
	}
	
	return nil
}

// GetMetrics returns current metrics
func (c *GRPCClient) GetMetrics() *Metrics {
	return c.metrics
}

// GetConnectionStats returns connection statistics
func (c *GRPCClient) GetConnectionStats() map[string]ConnectionStats {
	return c.connManager.GetConnectionStats()
}

// GetServiceDiscovery returns the service discovery instance
func (c *GRPCClient) GetServiceDiscovery() ServiceDiscovery {
	return c.serviceDiscovery
}