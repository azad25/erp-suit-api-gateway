package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"erp-api-gateway/internal/config"

	"github.com/gin-gonic/gin"
)

// Server represents the HTTP server
type Server struct {
	config     *config.Config
	router     *gin.Engine
	httpServer *http.Server
}

// New creates a new server instance
func New(cfg *config.Config) *Server {
	// Set Gin mode based on environment
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	
	server := &Server{
		config: cfg,
		router: router,
		httpServer: &http.Server{
			Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
			Handler:      router,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		},
	}

	server.setupRoutes()
	
	return server
}

// Start starts the HTTP server
func (s *Server) Start() error {
	fmt.Printf("Starting server on %s\n", s.httpServer.Addr)
	
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}
	
	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, s.config.Server.ShutdownTimeout)
	defer cancel()
	
	return s.httpServer.Shutdown(shutdownCtx)
}

// setupRoutes sets up the HTTP routes
func (s *Server) setupRoutes() {
	// Health check endpoints
	s.router.GET("/health", s.healthCheck)
	s.router.GET("/ready", s.readinessCheck)
	
	// Metrics endpoint (will be implemented later)
	s.router.GET("/metrics", s.metricsHandler)
	
	// API routes (will be implemented in later tasks)
	api := s.router.Group("/api/v1")
	{
		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/login", s.placeholderHandler("login"))
			auth.POST("/register", s.placeholderHandler("register"))
			auth.POST("/logout", s.placeholderHandler("logout"))
			auth.POST("/refresh", s.placeholderHandler("refresh"))
			auth.GET("/me", s.placeholderHandler("me"))
		}
	}
	
	// GraphQL endpoint (will be implemented later)
	s.router.POST("/graphql", s.placeholderHandler("graphql"))
	s.router.GET("/graphql", s.placeholderHandler("graphql-playground"))
	
	// WebSocket endpoint (will be implemented later)
	s.router.GET("/ws", s.placeholderHandler("websocket"))
}

// healthCheck handles health check requests
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"timestamp": time.Now().Unix(),
	})
}

// readinessCheck handles readiness check requests
func (s *Server) readinessCheck(c *gin.Context) {
	// TODO: Check dependencies (Redis, Kafka, gRPC services)
	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
		"timestamp": time.Now().Unix(),
	})
}

// metricsHandler handles Prometheus metrics requests
func (s *Server) metricsHandler(c *gin.Context) {
	// TODO: Implement Prometheus metrics
	c.String(http.StatusOK, "# Metrics endpoint - to be implemented")
}

// placeholderHandler is a temporary handler for routes that will be implemented later
func (s *Server) placeholderHandler(endpoint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"message": fmt.Sprintf("%s endpoint not yet implemented", endpoint),
			"status": "not_implemented",
		})
	}
}