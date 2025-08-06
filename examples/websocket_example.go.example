package main

import (
	"context"
	"crypto/rsa"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"erp-api-gateway/api/ws"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/services"
)

// This example demonstrates how to integrate the WebSocket handler into a Gin server
func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create a simple logger (in production, use the actual logger implementation)
	logger := &SimpleLogger{}

	// Initialize Redis client
	redisClient := services.NewRedisClient(&cfg.Redis, logger)
	defer redisClient.Close()

	// Create a mock JWT validator (in production, use the actual implementation)
	jwtValidator := &MockJWTValidator{}

	// Create WebSocket handler
	wsHandler := ws.NewHandler(&cfg.WebSocket, redisClient, logger, jwtValidator)
	defer wsHandler.Close()

	// Create Gin router
	router := gin.Default()

	// Add WebSocket endpoint
	router.GET("/ws", func(c *gin.Context) {
		if err := wsHandler.HandleConnection(c.Writer, c.Request); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
	})

	// Add health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":      "healthy",
			"connections": wsHandler.GetConnectionCount(),
		})
	})

	// Add example notification endpoint
	router.POST("/notify/:userID", func(c *gin.Context) {
		userID := c.Param("userID")
		
		var notification map[string]interface{}
		if err := c.ShouldBindJSON(&notification); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := wsHandler.PublishNotification(c.Request.Context(), userID, notification); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Notification sent"})
	})

	// Create HTTP server
	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		log.Println("WebSocket server starting on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown the server
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// SimpleLogger is a basic logger implementation for the example
type SimpleLogger struct{}

func (l *SimpleLogger) LogInfo(ctx context.Context, message string, fields map[string]interface{}) {
	log.Printf("INFO: %s %v", message, fields)
}

func (l *SimpleLogger) LogWarning(ctx context.Context, message string, fields map[string]interface{}) {
	log.Printf("WARNING: %s %v", message, fields)
}

func (l *SimpleLogger) LogError(ctx context.Context, message string, fields map[string]interface{}) {
	log.Printf("ERROR: %s %v", message, fields)
}

// MockJWTValidator is a mock JWT validator for the example
type MockJWTValidator struct{}

func (m *MockJWTValidator) ValidateToken(token string) (*interfaces.Claims, error) {
	// In a real implementation, this would validate the JWT token
	// For the example, we'll just return a mock user
	return &interfaces.Claims{
		UserID: "example-user-123",
		Email:  "user@example.com",
		Roles:  []string{"user"},
	}, nil
}

func (m *MockJWTValidator) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	// Mock implementation
	return nil, nil
}

func (m *MockJWTValidator) RefreshJWKS() error {
	// Mock implementation
	return nil
}