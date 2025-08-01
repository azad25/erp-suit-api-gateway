package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services/grpc_client"
)

func main() {
	// Create a sample configuration
	cfg := &config.GRPCConfig{
		AuthServiceAddress:        "localhost:50051",
		CRMServiceAddress:         "localhost:50052",
		HRMServiceAddress:         "localhost:50053",
		FinanceServiceAddress:     "localhost:50054",
		MaxRetries:                3,
		RetryInitialInterval:      100 * time.Millisecond,
		RetryMaxInterval:          30 * time.Second,
		RetryMultiplier:           2.0,
		RetryRandomFactor:         0.1,
		MaxConnections:            10,
		ConnectTimeout:            5 * time.Second,
		MaxIdleTime:               30 * time.Minute,
		MaxConnectionAge:          2 * time.Hour,
		KeepAliveTime:             30 * time.Second,
		KeepAliveTimeout:          5 * time.Second,
		EnableHealthCheck:         true,
		HealthCheckInterval:       30 * time.Second,
		CircuitBreakerMaxRequests: 5,
		CircuitBreakerInterval:    30 * time.Second,
		CircuitBreakerTimeout:     60 * time.Second,
	}

	// Initialize logger
	logger := logging.NewNoOpLogger()

	// Create gRPC client
	client, err := grpc_client.NewGRPCClient(cfg, logger)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer client.Close()

	fmt.Println("gRPC Client Example")
	fmt.Println("==================")

	// Demonstrate service discovery
	fmt.Println("\n1. Service Discovery:")
	services := []string{"auth", "crm", "hrm", "finance"}
	for _, service := range services {
		addr, err := client.GetServiceDiscovery().GetServiceAddress(service)
		if err != nil {
			fmt.Printf("   %s: Error - %v\n", service, err)
		} else {
			fmt.Printf("   %s: %s\n", service, addr)
		}
	}

	// Demonstrate health checks
	fmt.Println("\n2. Health Checks:")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthResults := client.HealthCheck(ctx)
	for service, healthy := range healthResults {
		status := "❌ Unhealthy"
		if healthy {
			status = "✅ Healthy"
		}
		fmt.Printf("   %s: %s\n", service, status)
	}

	// Demonstrate metrics
	fmt.Println("\n3. Connection Metrics:")
	metrics := client.GetMetrics()
	for _, service := range services {
		connMetrics := metrics.GetConnectionMetrics(service)
		fmt.Printf("   %s: Total=%d, Active=%d, Failed=%d\n",
			service,
			connMetrics.TotalConnections,
			connMetrics.ActiveConnections,
			connMetrics.FailedConnections,
		)
	}

	// Demonstrate connection stats
	fmt.Println("\n4. Connection Stats:")
	connStats := client.GetConnectionStats()
	for addr, stats := range connStats {
		status := "❌ Unhealthy"
		if stats.Healthy {
			status = "✅ Healthy"
		}
		fmt.Printf("   %s: State=%s, %s\n", addr, stats.State, status)
	}

	// Demonstrate retry functionality
	fmt.Println("\n5. Retry Example:")
	retryCount := 0
	err = client.CallWithRetry(ctx, "auth", func() error {
		retryCount++
		fmt.Printf("   Attempt %d\n", retryCount)
		if retryCount < 3 {
			return fmt.Errorf("simulated failure")
		}
		return nil
	})

	if err != nil {
		fmt.Printf("   Final result: Failed after retries - %v\n", err)
	} else {
		fmt.Printf("   Final result: Success after %d attempts\n", retryCount)
	}

	fmt.Println("\n✅ gRPC Client Example completed successfully!")
}

