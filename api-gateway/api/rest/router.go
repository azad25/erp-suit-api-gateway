package rest

import (
	"github.com/gin-gonic/gin"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/services/grpc_client"
)

// RouterConfig holds the configuration for setting up REST API routes
type RouterConfig struct {
	GRPCClient     *grpc_client.GRPCClient
	CacheService   interfaces.CacheService
	EventPublisher interfaces.EventPublisher
	Logger         interfaces.SimpleLogger
}

// SetupAuthRoutes sets up authentication-related routes
func SetupAuthRoutes(router *gin.Engine, config *RouterConfig) {
	// Create auth handler
	authHandler := NewAuthHandler(
		config.GRPCClient,
		config.CacheService,
		config.EventPublisher,
		config.Logger,
	)

	// Create auth route group
	authGroup := router.Group("/auth")
	{
		// Public routes (no authentication required)
		authGroup.POST("/login/", authHandler.Login)
		authGroup.POST("/register/", authHandler.Register)
		authGroup.POST("/refresh/", authHandler.RefreshToken)

		// Protected routes (authentication required)
		// Note: These would typically have authentication middleware applied
		authGroup.POST("/logout/", authHandler.Logout)
		authGroup.GET("/me/", authHandler.GetCurrentUser)
	}
}

// SetupAllRoutes sets up all REST API routes
func SetupAllRoutes(router *gin.Engine, config *RouterConfig) {
	// Setup authentication routes
	SetupAuthRoutes(router, config)

	// Add other route groups here as they are implemented
	// e.g., SetupCRMRoutes(router, config)
	// e.g., SetupHRMRoutes(router, config)
}