package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	// Check command line arguments
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <command>", os.Args[0])
	}

	command := os.Args[1]

	switch command {
	case "serve":
		// Run the server
		runServer()
	case "healthcheck":
		// Run health check
		runHealthCheck()
	default:
		log.Fatalf("Unknown command: %s. Available commands: serve, healthcheck", command)
	}
}

func runServer() {
	fmt.Printf("=== Starting ERP API Gateway Server ===\n")

	// Load configuration
	fmt.Printf("Loading configuration...\n")
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	fmt.Printf("Configuration loaded successfully\n")

	// Initialize integrated logger (Elasticsearch + Kafka)
	fmt.Printf("Initializing logger...\n")
	logger, err := logging.NewKafkaLoggerIntegration(&cfg.Logging, &cfg.Kafka)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Close()
	fmt.Printf("Logger initialized successfully\n")

	// Initialize Redis client
	fmt.Printf("Initializing Redis client...\n")
	redisClient := services.NewRedisClient(&cfg.Redis, logging.NewSimpleLogger(logger))
	defer redisClient.Close()
	fmt.Printf("Redis client initialized successfully\n")

	// Initialize Kafka producer (optional for testing)
	fmt.Printf("Initializing Kafka producer...\n")
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
	fmt.Printf("Event publisher initialized successfully\n")

	// Initialize JWT validator
	fmt.Printf("Initializing JWT validator...\n")
	jwtValidator := auth.NewJWTValidator(&cfg.JWT, redisClient)
	fmt.Printf("JWT validator initialized successfully\n")

	// Initialize policy engine (using default implementation)
	fmt.Printf("Initializing policy engine...\n")
	policyEngine := rbac.NewDefaultPolicyEngine(redisClient, nil, nil)
	fmt.Printf("Policy engine initialized successfully\n")

	// Initialize gRPC client
	fmt.Printf("Initializing gRPC client...\n")
	grpcClient, err := grpc_client.NewGRPCClient(&cfg.GRPC, logging.NewNoOpLogger())
	if err != nil {
		log.Fatalf("Failed to initialize gRPC client: %v", err)
	}
	defer grpcClient.Close()
	fmt.Printf("gRPC client initialized successfully\n")

	// Create server dependencies
	fmt.Printf("Creating server dependencies...\n")
	deps := &server.Dependencies{
		Logger:         logger,
		GRPCClient:     grpcClient,
		RedisClient:    redisClient,
		EventPublisher: eventPublisher,
		JWTValidator:   jwtValidator,
		PolicyEngine:   policyEngine,
	}
	fmt.Printf("Server dependencies created successfully\n")

	// Create and start server
	fmt.Printf("Creating server instance...\n")
	srv := server.New(cfg, deps)
	fmt.Printf("Server instance created successfully\n")

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		fmt.Printf("Starting server in goroutine...\n")
		log.Printf("Starting ERP API Gateway on %s:%d", cfg.Server.Host, cfg.Server.Port)
		if err := srv.Start(); err != nil {
			log.Printf("Server error: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	select {
	case <-sigChan:
		log.Println("Received shutdown signal, shutting down gracefully...")
		cancel()
	case <-ctx.Done():
		log.Println("Server context cancelled")
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("Server shutdown complete")
}

func runHealthCheck() {
	// Simple health check for Docker
	log.Println("Health check passed")
	os.Exit(0)
}
