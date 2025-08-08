// service/grpc_client/connection_manager.go
package grpc_client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// ConnectionManager manages gRPC connections with pooling and lifecycle management
type ConnectionManager struct {
	connections map[string]*grpc.ClientConn
	config      *ConnectionConfig
	mutex       sync.RWMutex
	healthCheck HealthChecker
}

// ConnectionConfig holds configuration for gRPC connections
type ConnectionConfig struct {
	MaxIdleTime        time.Duration
	MaxConnectionAge   time.Duration
	KeepAliveTime      time.Duration
	KeepAliveTimeout   time.Duration
	MaxConnections     int
	ConnectTimeout     time.Duration
	EnableHealthCheck  bool
	HealthCheckInterval time.Duration
	ServiceKey         string
}

// DefaultConnectionConfig returns a default configuration
func DefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		MaxIdleTime:         30 * time.Minute,
		MaxConnectionAge:    2 * time.Hour,
		KeepAliveTime:       60 * time.Second,    // Increased from 30s to 60s
		KeepAliveTimeout:    20 * time.Second,    // Increased from 5s to 20s
		MaxConnections:      10,
		ConnectTimeout:      10 * time.Second,
		EnableHealthCheck:   true,
		HealthCheckInterval: 60 * time.Second,    // Increased from 30s to 60s
	}
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(config *ConnectionConfig, healthCheck HealthChecker) *ConnectionManager {
	if config == nil {
		config = DefaultConnectionConfig()
	}

	cm := &ConnectionManager{
		connections: make(map[string]*grpc.ClientConn),
		config:      config,
		healthCheck: healthCheck,
	}

	return cm
}

// GetConnection returns a connection for the given service address
func (cm *ConnectionManager) GetConnection(ctx context.Context, address string) (*grpc.ClientConn, error) {
	cm.mutex.RLock()
	if conn, exists := cm.connections[address]; exists {
		cm.mutex.RUnlock()
		
		// Check if connection is healthy
		if cm.isConnectionHealthy(conn) {
			return conn, nil
		}
		
		// Connection is unhealthy, remove it and create a new one
		cm.mutex.Lock()
		delete(cm.connections, address)
		cm.mutex.Unlock()
		
		_ = conn.Close()
	} else {
		cm.mutex.RUnlock()
	}

	// Create new connection
	return cm.createConnection(ctx, address)
}

// createConnection creates a new gRPC connection
func (cm *ConnectionManager) createConnection(ctx context.Context, address string) (*grpc.ClientConn, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Double-check if connection was created by another goroutine
	if conn, exists := cm.connections[address]; exists && cm.isConnectionHealthy(conn) {
		return conn, nil
	}

	// Create connection context with timeout
	connCtx, cancel := context.WithTimeout(ctx, cm.config.ConnectTimeout)
	defer cancel()

	// Configure connection options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                cm.config.KeepAliveTime,
			Timeout:             cm.config.KeepAliveTimeout,
			PermitWithoutStream: false,  // Changed to false to reduce pings
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4*1024*1024), // 4MB
			grpc.MaxCallSendMsgSize(4*1024*1024), // 4MB
		),
	}
	
	// Create interceptor chain
	var interceptors []grpc.UnaryClientInterceptor
	
	// Add auth interceptor (always included)
	interceptors = append(interceptors, AuthInterceptor())
	
	// Add service key interceptor if service key is configured
	if cm.config.ServiceKey != "" {
		interceptors = append(interceptors, cm.serviceKeyInterceptor)
	}
	
	// Add interceptor chain to options
	if len(interceptors) > 0 {
		opts = append(opts, grpc.WithChainUnaryInterceptor(interceptors...))
	}

	// Create connection
	conn, err := grpc.DialContext(connCtx, address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}

	// Store connection
	cm.connections[address] = conn

	// Start health checking if enabled
	if cm.config.EnableHealthCheck && cm.healthCheck != nil {
		go cm.monitorConnection(address, conn)
	}

	return conn, nil
}

// isConnectionHealthy checks if a connection is healthy
func (cm *ConnectionManager) isConnectionHealthy(conn *grpc.ClientConn) bool {
	if conn == nil {
		return false
	}

	state := conn.GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// monitorConnection monitors a connection's health
func (cm *ConnectionManager) monitorConnection(address string, conn *grpc.ClientConn) {
	ticker := time.NewTicker(cm.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		cm.mutex.RLock()
		currentConn, exists := cm.connections[address]
		cm.mutex.RUnlock()

		if !exists || currentConn != conn {
			// Connection was replaced or removed
			return
		}

		if !cm.isConnectionHealthy(conn) {
			// Connection is unhealthy, perform health check
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			healthy := cm.healthCheck.CheckHealth(ctx, conn, address)
			cancel()

			if !healthy {
				// Remove unhealthy connection
				cm.mutex.Lock()
				if cm.connections[address] == conn {
					delete(cm.connections, address)
					_ = conn.Close()
				}
				cm.mutex.Unlock()
				return
			}
		}
	}
}

// Close closes all connections
func (cm *ConnectionManager) Close() error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	var errs []error
	for address, conn := range cm.connections {
		if err := conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection to %s: %w", address, err))
		}
	}

	cm.connections = make(map[string]*grpc.ClientConn)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing connections: %v", errs)
	}

	return nil
}

// GetConnectionStats returns statistics about connections
func (cm *ConnectionManager) GetConnectionStats() map[string]ConnectionStats {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	stats := make(map[string]ConnectionStats)
	for address, conn := range cm.connections {
		stats[address] = ConnectionStats{
			Address: address,
			State:   conn.GetState().String(),
			Healthy: cm.isConnectionHealthy(conn),
		}
	}

	return stats
}

// serviceKeyInterceptor adds service key header to outgoing gRPC requests
func (cm *ConnectionManager) serviceKeyInterceptor(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	// Add service key header to metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "x-service-key", cm.config.ServiceKey)
	
	// Call the original method
	return invoker(ctx, method, req, reply, cc, opts...)
}

// ConnectionStats holds statistics for a connection
type ConnectionStats struct {
	Address string `json:"address"`
	State   string `json:"state"`
	Healthy bool   `json:"healthy"`
}