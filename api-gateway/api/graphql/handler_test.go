package graphql

import (
	"testing"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
)

func TestNewGraphQLHandler(t *testing.T) {
	// Create mock dependencies
	cfg := &config.Config{
		Server: config.ServerConfig{
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"http://localhost:3000"},
			},
		},
	}
	
	logger := logging.NewNoOpLogger()
	
	// Create mock gRPC client (this would normally be properly initialized)
	grpcClient := &grpc_client.GRPCClient{}
	
	// Create mock Redis client (this would normally be properly initialized)
	redisClient := &services.RedisClient{}
	
	// Create mock Kafka producer (this would normally be properly initialized)
	kafkaProducer := &services.KafkaProducer{}
	
	// Test handler creation
	handler := NewGraphQLHandler(cfg, logger, grpcClient, redisClient, kafkaProducer)
	
	if handler == nil {
		t.Fatal("Expected handler to be created, got nil")
	}
	
	if handler.config != cfg {
		t.Error("Expected config to be set correctly")
	}
	
	if handler.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
	
	if handler.grpcClient != grpcClient {
		t.Error("Expected gRPC client to be set correctly")
	}
	
	if handler.redisClient != redisClient {
		t.Error("Expected Redis client to be set correctly")
	}
	
	if handler.kafkaProducer != kafkaProducer {
		t.Error("Expected Kafka producer to be set correctly")
	}
	
	if handler.dataLoader == nil {
		t.Error("Expected DataLoader to be initialized")
	}
	
	if handler.server == nil {
		t.Error("Expected GraphQL server to be initialized")
	}
}