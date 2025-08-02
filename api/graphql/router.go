package graphql

import (
	"github.com/gin-gonic/gin"
	
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
)

// RouterConfig holds the configuration for setting up GraphQL routes
type RouterConfig struct {
	Config        *config.Config
	Logger        logging.Logger
	GRPCClient    *grpc_client.GRPCClient
	RedisClient   *services.RedisClient
	KafkaProducer *services.KafkaProducer
}

// SetupGraphQLRoutes sets up GraphQL-related routes
func SetupGraphQLRoutes(router *gin.Engine, config *RouterConfig) {
	// Create GraphQL handler
	graphqlHandler := NewGraphQLHandler(
		config.Config,
		config.Logger,
		config.GRPCClient,
		config.RedisClient,
		config.KafkaProducer,
	)

	// GraphQL endpoint
	router.POST("/graphql", graphqlHandler.ServeHTTP())
	router.GET("/graphql", graphqlHandler.ServeHTTP())

	// GraphQL Playground (always available for now - can be controlled via config later)
	router.GET("/playground", graphqlHandler.PlaygroundHandler())
}