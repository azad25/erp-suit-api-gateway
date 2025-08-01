// service/grpc_client/health_checker.go
package grpc_client

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/health/grpc_health_v1"

	"erp-api-gateway/internal/logging"
)

// HealthChecker interface defines health checking functionality
type HealthChecker interface {
	CheckHealth(ctx context.Context, conn *grpc.ClientConn, service string) bool
	StartPeriodicHealthCheck(ctx context.Context, conn *grpc.ClientConn, service string, interval time.Duration) <-chan bool
	GetHealthStatus(service string) HealthStatus
	Stop()
}

// HealthStatus represents the health status of a service
type HealthStatus struct {
	Service     string                     `json:"service"`
	Status      grpc_health_v1.HealthCheckResponse_ServingStatus `json:"status"`
	LastCheck   time.Time                  `json:"last_check"`
	LastSuccess time.Time                  `json:"last_success"`
	Healthy     bool                       `json:"healthy"`
	Error       string                     `json:"error,omitempty"`
}

// HealthCheckerImpl implements the HealthChecker interface
type HealthCheckerImpl struct {
	logger          logging.Logger
	healthStatuses  map[string]*HealthStatus
	stopChannels    map[string]chan struct{}
	mutex           sync.RWMutex
	checkTimeout    time.Duration
	retryInterval   time.Duration
	maxRetries      int
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger logging.Logger) HealthChecker {
	return &HealthCheckerImpl{
		logger:         logger,
		healthStatuses: make(map[string]*HealthStatus),
		stopChannels:   make(map[string]chan struct{}),
		checkTimeout:   5 * time.Second,
		retryInterval:  10 * time.Second,
		maxRetries:     3,
	}
}

// CheckHealth performs a single health check on a service
func (hc *HealthCheckerImpl) CheckHealth(ctx context.Context, conn *grpc.ClientConn, service string) bool {
	if conn == nil {
		return false
	}

	// Check connection state first
	state := conn.GetState()
	if state != connectivity.Ready && state != connectivity.Idle {
		return false
	}

	// Try to create a health check client
	healthClient := grpc_health_v1.NewHealthClient(conn)
	
	// Create a timeout context for the health check
	checkCtx, cancel := context.WithTimeout(ctx, hc.checkTimeout)
	defer cancel()
	
	// Perform the health check
	resp, err := healthClient.Check(checkCtx, &grpc_health_v1.HealthCheckRequest{
		Service: service,
	})
	
	if err != nil {
		hc.logger.Error("Health check failed",
			map[string]interface{}{
				"service": service,
				"error":   err.Error(),
			})
		return false
	}
	
	return resp.Status == grpc_health_v1.HealthCheckResponse_SERVING
}

// StartPeriodicHealthCheck starts periodic health checking for a service
func (hc *HealthCheckerImpl) StartPeriodicHealthCheck(ctx context.Context, conn *grpc.ClientConn, service string, interval time.Duration) <-chan bool {
	resultChan := make(chan bool, 1)
	
	hc.mutex.Lock()
	// Stop existing health check if any
	if stopChan, exists := hc.stopChannels[service]; exists {
		close(stopChan)
	}
	
	stopChan := make(chan struct{})
	hc.stopChannels[service] = stopChan
	hc.mutex.Unlock()
	
	go func() {
		defer close(resultChan)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopChan:
				return
			case <-ticker.C:
				healthy := hc.CheckHealth(ctx, conn, service)
				
				hc.mutex.Lock()
				if hc.healthStatuses[service] == nil {
					hc.healthStatuses[service] = &HealthStatus{Service: service}
				}
				status := hc.healthStatuses[service]
				status.LastCheck = time.Now()
				status.Healthy = healthy
				if healthy {
					status.LastSuccess = time.Now()
					status.Status = grpc_health_v1.HealthCheckResponse_SERVING
					status.Error = ""
				} else {
					status.Status = grpc_health_v1.HealthCheckResponse_NOT_SERVING
					status.Error = "Health check failed"
				}
				hc.mutex.Unlock()
				
				select {
				case resultChan <- healthy:
				default:
					// Channel is full, skip this result
				}
			}
		}
	}()
	
	return resultChan
}

// GetHealthStatus returns the current health status for a service
func (hc *HealthCheckerImpl) GetHealthStatus(service string) HealthStatus {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()
	
	if status, exists := hc.healthStatuses[service]; exists {
		// Return a copy to avoid race conditions
		statusCopy := *status
		return statusCopy
	}
	
	return HealthStatus{
		Service: service,
		Status:  grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN,
		Healthy: false,
	}
}

// Stop stops all health checking
func (hc *HealthCheckerImpl) Stop() {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	
	for service, stopChan := range hc.stopChannels {
		close(stopChan)
		delete(hc.stopChannels, service)
	}
}