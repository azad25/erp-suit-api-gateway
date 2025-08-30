package server

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/url"
	"net/http"
	"strings"
	"time"

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

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
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
			deps.GRPCClient,
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
		AllowHeaders:     append(s.config.Server.CORS.AllowedHeaders, "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol"),
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
	fmt.Printf("Setting up routes...\n")

	// Health check endpoints (no authentication required)
	s.router.GET("/health", s.healthCheck)
	s.router.GET("/ready", s.readinessCheck)
	s.router.GET("/health/detailed", s.detailedHealthCheck)
	fmt.Printf("Health routes registered\n")

	// Test route
	s.router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Test route working"})
	})
	fmt.Printf("Test route registered: /test\n")

	// Metrics endpoint (no authentication required)
	s.router.GET("/metrics", s.metricsHandler)
	fmt.Printf("Metrics route registered\n")

	// WebSocket endpoints - using local handler
	s.router.GET("/ws", s.optionalAuth(), s.handleWebSocket)
	fmt.Printf("WebSocket route registered: /ws\n")

	// AI WebSocket endpoint - handle directly with authentication
	// Allow OPTIONS method for CORS preflight
	fmt.Printf("Registering AI WebSocket chat route: /ws/chat\n")
	s.router.OPTIONS("/ws/chat", func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Authorization, Content-Type")
		c.Status(http.StatusOK)
	})
	s.router.GET("/ws/chat", s.requireAuth(), s.handleAIWebSocket)
	fmt.Printf("AI WebSocket chat route registered successfully\n")

	// GraphQL endpoints
	s.setupGraphQLRoutes()
	fmt.Printf("GraphQL routes registered\n")

	// REST API routes
	s.setupRESTRoutes()
	fmt.Printf("REST routes registered\n")

	fmt.Printf("All routes setup completed\n")
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

		// AI Copilot routes - use consolidated router setup
		rest.SetupAIRoutes(v1, routerConfig)

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

// getRESTAIHandler creates and returns a REST AI proxy handler
func (s *Server) getRESTAIHandler(config *rest.RouterConfig) *rest.AIProxyHandler {
	return rest.NewAIProxyHandler("http://ai-copilot:8003")
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

// websocketProxy proxies WebSocket connections to a target server
type websocketProxy struct {
	target string
	headers http.Header
}

// ServeHTTP handles the WebSocket connection and proxies it to the target server
func (p *websocketProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	// Create a dialer with the same settings as the client
	dialer := &websocket.Dialer{
		HandshakeTimeout: 45 * time.Second,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
	}

	// Create a new request to the target server
	targetURL, err := url.Parse(p.target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %v", err)
	}

	// Set up the request headers
	headers := make(http.Header)
	
	// Copy the original headers
	for k, v := range r.Header {
		headers[k] = v
	}

	// Override with any custom headers from the proxy
	for k, v := range p.headers {
		headers[k] = v
	}

	// Set the WebSocket specific headers
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")
	headers.Set("Sec-WebSocket-Version", "13")

	// Make sure we have a valid WebSocket key
	if headers.Get("Sec-WebSocket-Key") == "" {
		headers.Set("Sec-WebSocket-Key", generateWebSocketKey())
	}

	// Connect to the target WebSocket server
	serverConn, resp, err := dialer.Dial(targetURL.String(), headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("websocket: bad handshake (status: %d, body: %v)", resp.StatusCode, resp.Body)
		}
		return fmt.Errorf("error dialing target server: %v", err)
	}
	defer serverConn.Close()

	// Upgrade the client connection
	upgrader := websocket.Upgrader{
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		CheckOrigin:      func(r *http.Request) bool { return true },
	}

	// Set response headers for WebSocket upgrade
	headers = make(http.Header)
	headers.Set("Upgrade", "websocket")
	headers.Set("Connection", "Upgrade")
	headers.Set("Sec-WebSocket-Accept", generateWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))

	// Upgrade the client connection
	clientConn, err := upgrader.Upgrade(w, r, headers)
	if err != nil {
		return fmt.Errorf("error upgrading client connection: %v", err)
	}
	defer clientConn.Close()

	// Start proxying messages in both directions
	errChan := make(chan error, 2)

	// Client to server messages
	go func() {
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				errChan <- fmt.Errorf("error reading from client: %v", err)
				return
			}
			if err := serverConn.WriteMessage(msgType, msg); err != nil {
				errChan <- fmt.Errorf("error writing to server: %v", err)
				return
			}
		}
	}()

	// Server to client messages
	go func() {
		for {
			msgType, msg, err := serverConn.ReadMessage()
			if err != nil {
				errChan <- fmt.Errorf("error reading from server: %v", err)
				return
			}
			if err := clientConn.WriteMessage(msgType, msg); err != nil {
				errChan <- fmt.Errorf("error writing to client: %v", err)
				return
			}
		}
	}()

	// Wait for an error from either goroutine
	return <-errChan
}

// generateWebSocketKey generates a random WebSocket key
func generateWebSocketKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// generateWebSocketAccept generates the WebSocket accept key
func generateWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// getWebSocketConnectionCount returns the number of active WebSocket connections
func (s *Server) getWebSocketConnectionCount() int {
	if s.wsHandler == nil {
		return 0
	}
	return s.wsHandler.GetConnectionCount()
}

// handleAIWebSocket handles AI chat WebSocket connections by proxying to the AI service
func (s *Server) handleAIWebSocket(c *gin.Context) {
	// Get user ID from authenticated context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user ID as string
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Log the AI WebSocket connection attempt
	s.logger.LogEvent(c.Request.Context(), interfaces.EventLogEntry{
		Timestamp:     time.Now(),
		EventID:       "ai_websocket_connect",
		EventType:     "websocket_connection",
		UserID:        userIDStr,
		CorrelationID: c.GetHeader("X-Request-ID"),
		Source:        "api-gateway",
		Data: map[string]interface{}{
			"endpoint": "/ws/chat",
			"remote_addr": c.Request.RemoteAddr,
			"user_agent": c.Request.UserAgent(),
		},
		Success: true,
	})

	// Set CORS headers for WebSocket
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Authorization, Content-Type")

	// Handle preflight OPTIONS request
	if c.Request.Method == "OPTIONS" {
		c.Status(http.StatusOK)
		return
	}

	// Ensure the connection is a WebSocket upgrade request
	if !c.IsWebsocket() {
		s.logger.LogError(c.Request.Context(), interfaces.ErrorLogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   "Not a WebSocket connection",
			Error:     "Expected WebSocket upgrade request",
			Service:   "api-gateway",
			Component: "server",
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Expected WebSocket upgrade request"})
		return
	}

	// Get the authentication token
	token := c.GetHeader("Authorization")
	if token == "" {
		token = c.Query("token")
	}

	// Ensure the token has the Bearer prefix
	if token != "" && !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + strings.TrimSpace(token)
	}

	// Build the target URL
	targetURL := fmt.Sprintf("ws://%s:%d/ws/chat", 
		s.config.WebSocket.ServerHost, 
		s.config.WebSocket.ServerPort)

	// Log the target URL for debugging
	s.logger.LogEvent(c.Request.Context(), interfaces.EventLogEntry{
		Timestamp: time.Now(),
		EventID:   "ai_websocket_proxy",
		EventType: "websocket_proxy",
		UserID:    userIDStr,
		Source:    "api-gateway",
		Data: map[string]interface{}{
			"target_url": targetURL,
			"has_token":  token != "",
		},
		Success: true,
	})

	// Create a new WebSocket proxy to the AI service
	proxy := &websocketProxy{
		target: targetURL,
		headers: http.Header{
			"Authorization": {token},
			"X-Forwarded-For":  {c.Request.RemoteAddr},
			"X-Forwarded-Host": {c.Request.Host},
			"X-Forwarded-Proto": {"ws"},
			"X-Real-IP":        {c.ClientIP()},
		},
	}

	// Create a new request with the updated headers
	req := c.Request.Clone(context.Background())
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	// Copy other necessary headers
	headersToCopy := []string{"Origin", "User-Agent", "X-Request-ID", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol"}
	for _, h := range headersToCopy {
		if val := c.GetHeader(h); val != "" {
			req.Header.Set(h, val)
		}
	}

	// Set the request URL to the target URL
	req.URL, _ = url.Parse(targetURL)
	req.RequestURI = ""

	// Log the request details
	s.logger.LogEvent(c.Request.Context(), interfaces.EventLogEntry{
		Timestamp: time.Now(),
		EventID:   "websocket_proxy_debug",
		EventType: "debug",
		Source:    "api-gateway",
		Data: map[string]interface{}{
			"target_url": targetURL,
			"headers":    req.Header,
			"message":    "Proxying WebSocket connection",
		},
		Success: true,
	})

	// Serve the WebSocket connection
	err := proxy.ServeHTTP(c.Writer, req)
	if err != nil && err != http.ErrServerClosed {
		s.logger.LogError(c.Request.Context(), interfaces.ErrorLogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   "WebSocket proxy error",
			Error:     err.Error(),
			Service:   "api-gateway",
			Component: "websocket_proxy",
		})
	}
}
