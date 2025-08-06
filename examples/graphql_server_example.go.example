package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"erp-api-gateway/api/graphql"
	"erp-api-gateway/api/rest"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
	"erp-api-gateway/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger := logging.NewNoOpLogger() // Replace with actual logger implementation

	// Initialize gRPC client
	grpcClient, err := grpc_client.NewGRPCClient(&cfg.GRPC, logger)
	if err != nil {
		log.Fatalf("Failed to initialize gRPC client: %v", err)
	}
	defer grpcClient.Close()

	// Initialize Redis client (optional for this example)
	var redisClient *services.RedisClient
	if cfg.Redis.Host != "" {
		redisClient, err = services.NewRedisClient(&cfg.Redis, logger)
		if err != nil {
			log.Printf("Warning: Failed to initialize Redis client: %v", err)
		}
	}

	// Initialize Kafka producer (optional for this example)
	var kafkaProducer *services.KafkaProducer
	if len(cfg.Kafka.Brokers) > 0 {
		kafkaProducer, err = services.NewKafkaProducer(&cfg.Kafka, logger)
		if err != nil {
			log.Printf("Warning: Failed to initialize Kafka producer: %v", err)
		}
		if kafkaProducer != nil {
			defer kafkaProducer.Close()
		}
	}

	// Create Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Add CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

	// Setup REST API routes
	restConfig := &rest.RouterConfig{
		GRPCClient:     grpcClient,
		CacheService:   redisClient,
		EventPublisher: kafkaProducer,
		Logger:         logger,
	}
	rest.SetupAllRoutes(router, restConfig)

	// Setup GraphQL routes
	graphqlConfig := &graphql.RouterConfig{
		Config:        cfg,
		Logger:        logger,
		GRPCClient:    grpcClient,
		RedisClient:   redisClient,
		KafkaProducer: kafkaProducer,
	}
	graphql.SetupGraphQLRoutes(router, graphqlConfig)

	// Add health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting GraphQL API Gateway on port %d", cfg.Server.Port)
		log.Printf("GraphQL endpoint: http://localhost:%d/graphql", cfg.Server.Port)
		log.Printf("GraphQL Playground: http://localhost:%d/playground", cfg.Server.Port)
		log.Printf("Health check: http://localhost:%d/health", cfg.Server.Port)
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down gracefully...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}

	log.Println("Shutdown complete")
}