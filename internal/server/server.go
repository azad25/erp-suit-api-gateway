package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"erp-api-gateway/api/graphql"
	"erp-api-gateway/api/rest"
	"erp-api-gateway/api/ws"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/health"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
	"erp-api-gateway/middleware"
)

// Server represents the HTTP server
type Server struct {
	config         *config.Config
	router         *gin.Engine
	httpServer     *http.Server
	logger         interfaces.Logger
	grpcClient     *grpc_client.GRPCClient
	redisClient    *services.RedisClient
	eventPublisher interfaces.EventPublisher
	jwtValidator   interfaces.JWTValidator
	policyEngine   interfaces.PolicyEngine
	wsHandler      *ws.Handler
	graphqlHandler *graphql.GraphQLHandler
	healthManager  *health.HealthManager
}

// Dependencies holds all the dependencies needed by the server
type Dependencies struct {
	Logger         interfaces.Logger
	GRPCClient     *grpc_client.GRPCClient
	RedisClient    *services.RedisClient
	EventPublisher interfaces.EventPublisher
	JWTValidator   interfaces.JWTValidator
	PolicyEngine   interfaces.PolicyEngine
}

// New creates a new server instance
func New(cfg *config.Config, deps *Dependencies) *Server {
	// Set Gin mode based on environment
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router without default middleware
	router := gin.New()

	// Create WebSocket handler (only if Redis client is available)
	var wsHandler *ws.Handler
	if deps.RedisClient != nil {
		wsHandler = ws.NewHandler(
			&cfg.WebSocket,
			deps.RedisClient,
			logging.NewSimpleLogger(deps.Logger),
			deps.JWTValidator,
		)
	}

	// Create GraphQL handler (local)
	graphqlHandler := graphql.NewGraphQLHandler(
		cfg,
		logging.NewNoOpLogger(),
		deps.GRPCClient,
		deps.RedisClient,
		deps.EventPublisher,
	)

	// Note: Removed GraphQL and WebSocket proxies - using local handlers instead

	// Create optimized health manager
	healthManager := health.NewHealthManager(logging.NewSimpleLogger(deps.Logger))

	// Register health checkers
	if deps.RedisClient != nil {
		healthManager.RegisterChecker(health.NewRedisHealthChecker(deps.RedisClient))
	}

	if deps.GRPCClient != nil {
		healthManager.RegisterChecker(health.NewGRPCHealthChecker(deps.GRPCClient, "auth"))
	}

	// Register Kafka health checker only if EventPublisher is a KafkaProducer
	if kafkaProducer, ok := deps.EventPublisher.(*services.KafkaProducer); ok {
		healthManager.RegisterChecker(health.NewKafkaHealthChecker(kafkaProducer))
	}

	// Note: Removed health checkers for non-existent infrastructure services

	server := &Server{
		config:         cfg,
		router:         router,
		logger:         deps.Logger,
		grpcClient:     deps.GRPCClient,
		redisClient:    deps.RedisClient,
		eventPublisher: deps.EventPublisher,
		jwtValidator:   deps.JWTValidator,
		policyEngine:   deps.PolicyEngine,
		wsHandler:      wsHandler,
		graphqlHandler: graphqlHandler,
		healthManager:  healthManager,
		httpServer: &http.Server{
			Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
			Handler:      router,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		},
	}

	server.setupMiddleware()
	server.setupRoutes()

	return server
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Start health manager
	s.healthManager.Start()

	fmt.Printf("Starting server on %s\n", s.httpServer.Addr)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	fmt.Println("Shutting down server...")

	// Stop health manager
	s.healthManager.Stop()

	// Close WebSocket handler
	if s.wsHandler != nil {
		if err := s.wsHandler.Close(); err != nil {
			fmt.Printf("Error closing WebSocket handler: %v\n", err)
		}
	}

	// Shutdown HTTP server with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, s.config.Server.ShutdownTimeout)
	defer cancel()

	return s.httpServer.Shutdown(shutdownCtx)
}

// setupMiddleware sets up the middleware chain
func (s *Server) setupMiddleware() {
	// Create middleware instances
	loggingMiddleware := middleware.NewLoggingMiddleware(s.logger)
	authMiddleware := middleware.NewAuthMiddleware(s.jwtValidator, s.redisClient)
	rbacMiddleware := middleware.NewRBACMiddleware(s.policyEngine, nil)

	// Recovery middleware (must be first)
	s.router.Use(loggingMiddleware.PanicRecovery())

	// Request logging middleware
	s.router.Use(loggingMiddleware.RequestLogger())

	// CORS middleware
	s.router.Use(s.setupCORS())

	// Rate limiting middleware
	s.router.Use(s.setupRateLimit())

	// Request timeout middleware
	s.router.Use(s.setupRequestTimeout())

	// Error logging middleware (should be last)
	s.router.Use(loggingMiddleware.ErrorLogger())

	// Store middleware instances for use in route setup
	s.router.Use(func(c *gin.Context) {
		c.Set("auth_middleware", authMiddleware)
		c.Set("rbac_middleware", rbacMiddleware)
		c.Next()
	})
}

// setupCORS sets up CORS middleware
func (s *Server) setupCORS() gin.HandlerFunc {
	corsConfig := cors.Config{
		AllowOrigins:     s.config.Server.CORS.AllowedOrigins,
		AllowMethods:     s.config.Server.CORS.AllowedMethods,
		AllowHeaders:     s.config.Server.CORS.AllowedHeaders,
		AllowCredentials: s.config.Server.CORS.AllowCredentials,
		MaxAge:           time.Duration(s.config.Server.CORS.MaxAge) * time.Second,
	}

	return cors.New(corsConfig)
}

// setupRateLimit sets up rate limiting middleware
func (s *Server) setupRateLimit() gin.HandlerFunc {
	// Create a rate limiter (100 requests per minute per IP)
	limiter := rate.NewLimiter(rate.Every(time.Minute/100), 100)

	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"message": "Rate limit exceeded",
				"errors":  map[string][]string{"rate_limit": {"Too many requests"}},
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// setupRequestTimeout sets up request timeout middleware
func (s *Server) setupRequestTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set a timeout for the request context
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// setupRoutes sets up the HTTP routes
func (s *Server) setupRoutes() {
	// Health check endpoints (no authentication required)
	s.router.GET("/health", s.healthCheck)
	s.router.GET("/ready", s.readinessCheck)
	s.router.GET("/health/detailed", s.detailedHealthCheck)

	// Metrics endpoint (no authentication required)
	s.router.GET("/metrics", s.metricsHandler)

	// WebSocket endpoints - using local handler
	s.router.GET("/ws", s.optionalAuth(), s.handleWebSocket)

	// GraphQL endpoints
	s.setupGraphQLRoutes()

	// REST API routes
	s.setupRESTRoutes()
}

// setupGraphQLRoutes sets up GraphQL routes
func (s *Server) setupGraphQLRoutes() {
	// Use local GraphQL handler directly
	// POST requests for GraphQL operations - use optional auth to allow both authenticated and unauthenticated queries
	s.router.POST("/graphql", s.optionalAuth(), s.graphqlHandler.ServeHTTP())

	// GET requests for GraphQL operations (introspection, etc.) - no auth required
	s.router.GET("/graphql", s.graphqlHandler.ServeHTTP())

	// GraphQL Playground (development only)
	if s.config.IsDevelopment() {
		s.router.GET("/playground", s.graphqlHandler.PlaygroundHandler())
	}
}

// setupRESTRoutes sets up REST API routes
func (s *Server) setupRESTRoutes() {
	// Create router config for REST handlers
	routerConfig := &rest.RouterConfig{
		GRPCClient:     s.grpcClient,
		CacheService:   s.redisClient,
		EventPublisher: s.eventPublisher,
		Logger:         logging.NewSimpleLogger(s.logger),
	}

	// Authentication routes (no auth required for login/register)
	authGroup := s.router.Group("/auth")
	{
		// Public routes
		authGroup.POST("/login", s.getRESTAuthHandler(routerConfig).Login)
		authGroup.POST("/register", s.getRESTAuthHandler(routerConfig).Register)
		authGroup.POST("/refresh", s.getRESTAuthHandler(routerConfig).RefreshToken)

		// Protected routes
		authGroup.POST("/logout", s.requireAuth(), s.getRESTAuthHandler(routerConfig).Logout)
		authGroup.GET("/me", s.requireAuth(), s.getRESTAuthHandler(routerConfig).GetCurrentUser)
	}

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Authentication routes (alternative paths)
		authV1 := v1.Group("/auth")
		{
			// Public routes
			authV1.POST("/login", s.getRESTAuthHandler(routerConfig).Login)
			authV1.POST("/register", s.getRESTAuthHandler(routerConfig).Register)
			authV1.POST("/refresh", s.getRESTAuthHandler(routerConfig).RefreshToken)

			// Protected routes
			authV1.POST("/logout", s.requireAuth(), s.getRESTAuthHandler(routerConfig).Logout)
			authV1.GET("/me", s.requireAuth(), s.getRESTAuthHandler(routerConfig).GetCurrentUser)
		}

		// Future API routes will be added here
		// e.g., CRM, HRM, Finance routes
	}
}

// getRESTAuthHandler creates and returns a REST auth handler
func (s *Server) getRESTAuthHandler(config *rest.RouterConfig) *rest.AuthHandler {
	return rest.NewAuthHandler(
		config.GRPCClient,
		config.CacheService,
		config.EventPublisher,
		config.Logger,
	)
}

// Middleware helper functions

// requireAuth returns middleware that requires authentication
func (s *Server) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authMiddleware, exists := c.Get("auth_middleware")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Authentication middleware not available",
			})
			c.Abort()
			return
		}

		authMW := authMiddleware.(*middleware.AuthMiddleware)
		authMW.RequireAuth()(c)
	}
}

// optionalAuth returns middleware that optionally validates authentication
func (s *Server) optionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authMiddleware, exists := c.Get("auth_middleware")
		if !exists {
			c.Next()
			return
		}

		authMW := authMiddleware.(*middleware.AuthMiddleware)
		authMW.OptionalJWT()(c)
	}
}

// requirePermission returns middleware that requires a specific permission
func (s *Server) requirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First require authentication
		s.requireAuth()(c)
		if c.IsAborted() {
			return
		}

		// Then check permission
		rbacMiddleware, exists := c.Get("rbac_middleware")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "RBAC middleware not available",
			})
			c.Abort()
			return
		}

		rbacMW := rbacMiddleware.(*middleware.RBACMiddleware)
		rbacMW.RequirePermission(permission)(c)
	}
}

// requireRole returns middleware that requires a specific role
func (s *Server) requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First require authentication
		s.requireAuth()(c)
		if c.IsAborted() {
			return
		}

		// Then check role
		rbacMiddleware, exists := c.Get("rbac_middleware")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "RBAC middleware not available",
			})
			c.Abort()
			return
		}

		rbacMW := rbacMiddleware.(*middleware.RBACMiddleware)
		rbacMW.RequireRole(role)(c)
	}
}

// Route handlers

// handleWebSocket handles WebSocket connection upgrades
func (s *Server) handleWebSocket(c *gin.Context) {
	if s.wsHandler == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"message": "WebSocket service not available",
			"errors":  map[string][]string{"websocket": {"WebSocket handler not initialized"}},
		})
		return
	}

	if err := s.wsHandler.HandleConnection(c.Writer, c.Request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "WebSocket connection failed",
			"errors":  map[string][]string{"websocket": {err.Error()}},
		})
	}
}

// healthCheck handles health check requests (fast, no dependency checks)
func (s *Server) healthCheck(c *gin.Context) {
	// Basic health check - just confirms the service is running
	health := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   "erp-api-gateway",
		"version":   "1.0.0",
	}

	c.JSON(http.StatusOK, health)
}

// readinessCheck handles readiness check requests (fast, uses cached health status)
func (s *Server) readinessCheck(c *gin.Context) {
	// Get cached health statuses (no blocking calls)
	statuses := s.healthManager.GetAllStatuses()
	ready := s.healthManager.IsHealthy()

	// Convert to response format
	checks := make(map[string]interface{})
	for name, status := range statuses {
		checks[name] = map[string]interface{}{
			"status":     status.Status,
			"last_check": status.LastCheck.Unix(),
			"latency_ms": status.Latency,
		}

		if status.Error != "" {
			checks[name].(map[string]interface{})["error"] = status.Error
		}
	}

	statusText := "ready"
	statusCode := http.StatusOK
	if !ready {
		statusText = "not_ready"
		statusCode = http.StatusServiceUnavailable
	}

	response := gin.H{
		"status":    statusText,
		"timestamp": time.Now().Unix(),
		"checks":    checks,
		"service":   "erp-api-gateway",
		"version":   "1.0.0",
	}

	c.JSON(statusCode, response)
}

// detailedHealthCheck provides detailed health information with optional force refresh
func (s *Server) detailedHealthCheck(c *gin.Context) {
	// Check if force refresh is requested
	forceRefresh := c.Query("force") == "true"

	var statuses map[string]*health.HealthStatus

	if forceRefresh {
		// Force fresh health checks (use sparingly)
		statuses = make(map[string]*health.HealthStatus)

		// Get list of registered checkers and force check each
		allStatuses := s.healthManager.GetAllStatuses()
		for serviceName := range allStatuses {
			statuses[serviceName] = s.healthManager.ForceCheck(serviceName)
		}
	} else {
		// Use cached statuses
		statuses = s.healthManager.GetAllStatuses()
	}

	// Calculate overall health
	healthy := 0
	unhealthy := 0
	stale := 0

	for _, status := range statuses {
		switch status.Status {
		case "healthy":
			healthy++
		case "unhealthy":
			unhealthy++
		case "stale":
			stale++
		}
	}

	overallStatus := "healthy"
	if unhealthy > 0 {
		overallStatus = "unhealthy"
	} else if stale > 0 {
		overallStatus = "degraded"
	}

	response := gin.H{
		"status":    overallStatus,
		"timestamp": time.Now().Unix(),
		"service":   "erp-api-gateway",
		"version":   "1.0.0",
		"summary": gin.H{
			"healthy":   healthy,
			"unhealthy": unhealthy,
			"stale":     stale,
			"total":     len(statuses),
		},
		"services":      statuses,
		"force_refresh": forceRefresh,
	}

	statusCode := http.StatusOK
	if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	} else if overallStatus == "degraded" {
		statusCode = http.StatusPartialContent
	}

	c.JSON(statusCode, response)
}

// metricsHandler handles Prometheus metrics requests
func (s *Server) metricsHandler(c *gin.Context) {
	// Basic metrics - will be enhanced in task 13
	metrics := fmt.Sprintf(`# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200"} 0
http_requests_total{method="POST",status="200"} 0

# HELP websocket_connections_active Number of active WebSocket connections
# TYPE websocket_connections_active gauge
websocket_connections_active %d

# HELP server_uptime_seconds Server uptime in seconds
# TYPE server_uptime_seconds counter
server_uptime_seconds %d
`, s.getWebSocketConnectionCount(), int(time.Now().Unix()))

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, metrics)
}

// getWebSocketConnectionCount returns the number of active WebSocket connections
func (s *Server) getWebSocketConnectionCount() int {
	if s.wsHandler == nil {
		return 0
	}
	return s.wsHandler.GetConnectionCount()
}
