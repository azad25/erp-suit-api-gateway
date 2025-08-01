package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services/grpc_client"
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

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx // Will be used for graceful shutdown in full implementation

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("gRPC API Gateway starting...")

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down gracefully...")

	// Perform cleanup
	if err := grpcClient.Close(); err != nil {
		log.Printf("Error closing gRPC client: %v", err)
	}

	log.Println("Shutdown complete")
}