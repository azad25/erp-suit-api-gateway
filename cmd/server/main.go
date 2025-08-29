package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"erp-api-gateway/internal/auth"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/rbac"
	"erp-api-gateway/internal/server"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize integrated logger (Elasticsearch + Kafka)
	logger, err := logging.NewKafkaLoggerIntegration(&cfg.Logging, &cfg.Kafka)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Close()

	// Initialize Redis client
	redisClient := services.NewRedisClient(&cfg.Redis, logging.NewSimpleLogger(logger))
	defer redisClient.Close()

	// Initialize Kafka producer (optional for testing)
	var eventPublisher interfaces.EventPublisher
	if cfg.Kafka.Enabled {
		kafkaProducer, err := services.NewKafkaProducer(&cfg.Kafka)
		if err != nil {
			log.Printf("Warning: Failed to initialize Kafka producer: %v", err)
			log.Println("Using no-op event publisher as fallback...")
			eventPublisher = services.NewNoOpEventPublisher()
		} else {
			log.Println("Kafka producer initialized successfully")
			eventPublisher = kafkaProducer
			defer kafkaProducer.Close()
		}
	} else {
		log.Println("Kafka is disabled, using no-op event publisher")
		eventPublisher = services.NewNoOpEventPublisher()
	}

	// Initialize JWT validator
	jwtValidator := auth.NewJWTValidator(&cfg.JWT, redisClient)

	// Initialize policy engine (using default implementation)
	policyEngine := rbac.NewDefaultPolicyEngine(redisClient, nil, nil)

	// Initialize gRPC client
	grpcClient, err := grpc_client.NewGRPCClient(&cfg.GRPC, logging.NewNoOpLogger())
	if err != nil {
		log.Fatalf("Failed to initialize gRPC client: %v", err)
	}
	defer grpcClient.Close()

	// Create server dependencies
	deps := &server.Dependencies{
		Logger:         logger,
		GRPCClient:     grpcClient,
		RedisClient:    redisClient,
		EventPublisher: eventPublisher,
		JWTValidator:   jwtValidator,
		PolicyEngine:   policyEngine,
	}

	// Create and start server
	srv := server.New(cfg, deps)

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting ERP API Gateway on %s:%d", cfg.Server.Host, cfg.Server.Port)
		if err := srv.Start(); err != nil {
			log.Printf("Server error: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	select {
	case <-sigChan:
		log.Println("Received shutdown signal")
	case <-ctx.Done():
		log.Println("Context cancelled")
	}

	log.Println("Shutting down gracefully...")

	// Shutdown server with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}

	log.Println("Shutdown complete")
}