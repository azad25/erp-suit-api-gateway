# ERP API Gateway - Developer Documentation

## Table of Contents
1. [Getting Started](#getting-started)
2. [Project Structure](#project-structure)
3. [Architecture Overview](#architecture-overview)
4. [Core Components](#core-components)
5. [Development Workflow](#development-workflow)
6. [Testing Guide](#testing-guide)
7. [Configuration Management](#configuration-management)
8. [Deployment Guide](#deployment-guide)
9. [Contributing Guidelines](#contributing-guidelines)
10. [Troubleshooting](#troubleshooting)

## Getting Started

### Prerequisites

- **Go 1.21+**: Latest stable version of Go
- **Docker**: For containerization and local development
- **Docker Compose**: For orchestrating local services
- **Redis**: For caching and pub/sub messaging
- **Apache Kafka**: For event streaming
- **Elasticsearch**: For structured logging
- **Protocol Buffers**: For gRPC service definitions

### Local Development Setup

1. **Clone the Repository**
```bash
git clone https://github.com/your-org/erp-api-gateway.git
cd erp-api-gateway
```

2. **Install Dependencies**
```bash
go mod download
go mod tidy
```

3. **Start Infrastructure Services**
```bash
docker-compose up -d redis kafka elasticsearch
```

4. **Generate Protocol Buffer Code**
```bash
# Install protoc and Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code from .proto files
make proto-gen
```

5. **Run the Application**
```bash
# Development mode with hot reload
go run cmd/server/main.go

# Or using make
make run-dev
```

6. **Verify Installation**
```bash
# Check health endpoint
curl http://localhost:8080/health

# Check readiness endpoint
curl http://localhost:8080/ready
```

### Environment Configuration

Create a `.env` file for local development:

```bash
# Server Configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0
LOG_LEVEL=debug

# gRPC Services
GRPC_AUTH_ADDRESS=localhost:50051
GRPC_CRM_ADDRESS=localhost:50052
GRPC_HRM_ADDRESS=localhost:50053
GRPC_FINANCE_ADDRESS=localhost:50054

# Redis Configuration
REDIS_ADDRESS=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0

# Kafka Configuration
KAFKA_BROKERS=localhost:9092
KAFKA_CLIENT_ID=api-gateway-dev

# JWT Configuration
JWT_PUBLIC_KEY_PATH=./certs/jwt-public.pem
JWT_JWKS_URL=http://localhost:50051/jwks
JWT_ALGORITHM=RS256

# Elasticsearch Configuration
ELASTICSEARCH_ADDRESSES=http://localhost:9200
ELASTICSEARCH_INDEX=api-gateway-logs-dev
```

## Project Structure

```
erp-api-gateway/
├── cmd/
│   └── server/
│       └── main.go                 # Application entry point
├── api/
│   ├── rest/                       # REST API handlers
│   │   ├── auth_handler.go
│   │   ├── auth_handler_test.go
│   │   └── handlers.go
│   ├── graphql/                    # GraphQL implementation
│   │   ├── handler.go
│   │   ├── handler_test.go
│   │   ├── schema/
│   │   │   ├── schema.graphql
│   │   │   └── resolvers.go
│   │   └── helpers/
│   │       └── conversion.go
│   └── ws/                         # WebSocket handlers
│       ├── handler.go
│       ├── handler_test.go
│       └── connection_manager.go
├── internal/
│   ├── config/                     # Configuration management
│   │   ├── config.go
│   │   └── config_test.go
│   ├── server/                     # HTTP server setup
│   │   ├── server.go
│   │   └── server_test.go
│   ├── services/                   # Business services
│   │   ├── grpc_client/
│   │   │   ├── grpc_client.go
│   │   │   └── grpc_client_test.go
│   │   ├── redis/
│   │   │   ├── redis_client.go
│   │   │   └── redis_client_test.go
│   │   └── kafka/
│   │       ├── kafka_producer.go
│   │       └── kafka_producer_test.go
│   ├── logging/                    # Logging infrastructure
│   │   ├── logger.go
│   │   ├── adapters.go
│   │   └── elasticsearch.go
│   └── auth/                       # Authentication utilities
│       ├── jwt_validator.go
│       ├── jwt_validator_test.go
│       └── claims.go
├── middleware/                     # HTTP middleware
│   ├── auth.go
│   ├── auth_test.go
│   ├── rbac.go
│   ├── rbac_test.go
│   ├── logger.go
│   ├── cors.go
│   └── rate_limiter.go
├── proto/                          # Protocol Buffer definitions
│   ├── auth/
│   │   ├── auth.proto
│   │   ├── auth.pb.go
│   │   └── auth_grpc.pb.go
│   ├── crm/
│   │   ├── crm.proto
│   │   ├── crm.pb.go
│   │   └── crm_grpc.pb.go
│   └── common/
│       └── common.proto
├── test/                           # Test utilities and integration tests
│   ├── integration_test.go
│   ├── load_test.go
│   ├── mocks/
│   │   ├── grpc_client_mock.go
│   │   ├── redis_client_mock.go
│   │   └── kafka_producer_mock.go
│   └── fixtures/
│       └── test_data.go
├── scripts/                        # Build and deployment scripts
│   ├── build.sh
│   ├── test.sh
│   └── deploy.sh
├── deployments/                    # Deployment configurations
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── docker-compose.yml
│   └── kubernetes/
│       ├── deployment.yaml
│       ├── service.yaml
│       └── configmap.yaml
├── docs/                          # Documentation
│   ├── api/
│   ├── architecture/
│   └── deployment/
├── config.yaml                    # Default configuration
├── go.mod                         # Go module definition
├── go.sum                         # Go module checksums
├── Makefile                       # Build automation
└── README.md                      # Project overview
```

### Directory Explanations

#### `/cmd/server/`
Contains the application entry point. This follows Go's standard project layout where `cmd` contains main applications.

#### `/api/`
Contains HTTP API handlers organized by protocol:
- `rest/`: REST API endpoints
- `graphql/`: GraphQL server and resolvers
- `ws/`: WebSocket handlers

#### `/internal/`
Contains private application code that shouldn't be imported by other applications:
- `config/`: Configuration loading and validation
- `server/`: HTTP server setup and middleware chain
- `services/`: Business logic and external service clients
- `logging/`: Structured logging implementation
- `auth/`: Authentication and authorization utilities

#### `/middleware/`
Contains HTTP middleware components that can be reused across different handlers.

#### `/proto/`
Contains Protocol Buffer definitions and generated Go code for gRPC communication.

#### `/test/`
Contains test utilities, mocks, and integration tests that span multiple packages.

## Architecture Overview

### Clean Architecture Principles

The codebase follows clean architecture principles with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    External Interfaces                      │
│  (REST API, GraphQL, WebSocket, gRPC, Redis, Kafka)        │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Interface Adapters                          │
│     (Handlers, Middleware, gRPC Clients, Repositories)     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Use Cases / Services                       │
│        (Authentication, Authorization, Event Publishing)    │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    Entities                                 │
│           (User, Claims, Events, Configuration)            │
└─────────────────────────────────────────────────────────────┘
```

### Dependency Injection

The application uses a simple dependency injection pattern:

```go
// Container holds all application dependencies
type Container struct {
    Config        *config.Config
    Logger        *logging.Logger
    GRPCClient    *grpc_client.Client
    RedisClient   *redis.Client
    KafkaProducer *kafka.Producer
    AuthValidator *auth.JWTValidator
}

// NewContainer creates and wires all dependencies
func NewContainer(cfg *config.Config) (*Container, error) {
    logger := logging.NewLogger(cfg.Logging)
    
    grpcClient, err := grpc_client.New(cfg.GRPC, logger)
    if err != nil {
        return nil, err
    }
    
    redisClient, err := redis.NewClient(cfg.Redis, logger)
    if err != nil {
        return nil, err
    }
    
    // ... wire other dependencies
    
    return &Container{
        Config:        cfg,
        Logger:        logger,
        GRPCClient:    grpcClient,
        RedisClient:   redisClient,
        // ... other dependencies
    }, nil
}
```

## Core Components

### 1. HTTP Server (`internal/server/server.go`)

The HTTP server is built using Gin framework with a carefully ordered middleware chain:

```go
type Server struct {
    router     *gin.Engine
    config     *config.Config
    container  *Container
    httpServer *http.Server
}

func (s *Server) setupMiddleware() {
    // Order is important - panic recovery should be first
    s.router.Use(gin.Recovery())
    
    // Request logging
    s.router.Use(middleware.RequestLogger(s.container.Logger))
    
    // CORS handling
    s.router.Use(middleware.CORS(s.config.Server.CORS))
    
    // Rate limiting
    s.router.Use(middleware.RateLimit(s.config.Server.RateLimit))
    
    // Request timeout
    s.router.Use(middleware.Timeout(s.config.Server.RequestTimeout))
}

func (s *Server) setupRoutes() {
    // Health endpoints (no auth required)
    s.router.GET("/health", s.healthHandler)
    s.router.GET("/ready", s.readinessHandler)
    s.router.GET("/metrics", s.metricsHandler)
    
    // Authentication endpoints
    authGroup := s.router.Group("/auth")
    {
        authHandler := rest.NewAuthHandler(s.container)
        authGroup.POST("/login/", authHandler.Login)
        authGroup.POST("/register/", authHandler.Register)
        authGroup.POST("/refresh/", authHandler.RefreshToken)
        
        // Protected auth endpoints
        protected := authGroup.Group("")
        protected.Use(middleware.RequireAuth(s.container.AuthValidator))
        protected.POST("/logout/", authHandler.Logout)
        protected.GET("/me/", authHandler.GetCurrentUser)
    }
    
    // GraphQL endpoint
    s.router.POST("/graphql", middleware.OptionalAuth(s.container.AuthValidator), 
        graphql.NewHandler(s.container))
    
    // WebSocket endpoint
    s.router.GET("/ws", middleware.RequireAuth(s.container.AuthValidator),
        ws.NewHandler(s.container))
}
```

### 2. Authentication Middleware (`middleware/auth.go`)

JWT-based authentication with Redis caching:

```go
type AuthMiddleware struct {
    validator   *auth.JWTValidator
    redisClient *redis.Client
    logger      *logging.Logger
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := m.extractToken(c)
        if token == "" {
            c.JSON(401, gin.H{"success": false, "message": "Authorization header required"})
            c.Abort()
            return
        }
        
        // Check cache first
        if claims, err := m.getCachedClaims(token); err == nil {
            c.Set("user_claims", claims)
            c.Next()
            return
        }
        
        // Validate token
        claims, err := m.validator.ValidateToken(token)
        if err != nil {
            c.JSON(401, gin.H{"success": false, "message": "Invalid token"})
            c.Abort()
            return
        }
        
        // Cache valid token
        m.cacheClaims(token, claims)
        
        c.Set("user_claims", claims)
        c.Next()
    }
}

func (m *AuthMiddleware) extractToken(c *gin.Context) string {
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
        return ""
    }
    
    parts := strings.SplitN(authHeader, " ", 2)
    if len(parts) != 2 || parts[0] != "Bearer" {
        return ""
    }
    
    return parts[1]
}
```

### 3. RBAC Middleware (`middleware/rbac.go`)

Role-based access control with permission caching:

```go
type RBACMiddleware struct {
    policyEngine *PolicyEngine
    redisClient  *redis.Client
    logger       *logging.Logger
}

func (m *RBACMiddleware) RequirePermission(permission string) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, exists := c.Get("user_claims")
        if !exists {
            c.JSON(401, gin.H{"success": false, "message": "Authentication required"})
            c.Abort()
            return
        }
        
        userClaims := claims.(*auth.Claims)
        
        // Check cached permissions
        if hasPermission, err := m.getCachedPermission(userClaims.UserID, permission); err == nil {
            if !hasPermission {
                c.JSON(403, gin.H{"success": false, "message": "Insufficient permissions"})
                c.Abort()
                return
            }
            c.Next()
            return
        }
        
        // Check permission using policy engine
        hasPermission := m.policyEngine.HasPermission(userClaims, permission)
        
        // Cache result
        m.cachePermission(userClaims.UserID, permission, hasPermission)
        
        if !hasPermission {
            c.JSON(403, gin.H{"success": false, "message": "Insufficient permissions"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}

type PolicyEngine struct {
    roleHierarchy map[string][]string
    permissions   map[string][]string
}

func (pe *PolicyEngine) HasPermission(claims *auth.Claims, permission string) bool {
    // Check direct permissions
    for _, userPerm := range claims.Permissions {
        if userPerm == permission {
            return true
        }
    }
    
    // Check role-based permissions
    for _, role := range claims.Roles {
        if rolePerms, exists := pe.permissions[role]; exists {
            for _, rolePerm := range rolePerms {
                if rolePerm == permission {
                    return true
                }
            }
        }
    }
    
    return false
}
```

### 4. gRPC Client Service (`internal/services/grpc_client/grpc_client.go`)

Manages connections to backend microservices with connection pooling and circuit breaker:

```go
type Client struct {
    connections map[string]*grpc.ClientConn
    config      *config.GRPCConfig
    logger      *logging.Logger
    metrics     *metrics.GRPCMetrics
    circuitBreakers map[string]*CircuitBreaker
}

func (c *Client) AuthService() authpb.AuthServiceClient {
    conn := c.getConnection("auth")
    return authpb.NewAuthServiceClient(conn)
}

func (c *Client) getConnection(serviceName string) *grpc.ClientConn {
    if conn, exists := c.connections[serviceName]; exists {
        return conn
    }
    
    // Create new connection with retry and circuit breaker
    conn, err := c.createConnection(serviceName)
    if err != nil {
        c.logger.Error("Failed to create gRPC connection", 
            "service", serviceName, "error", err)
        return nil
    }
    
    c.connections[serviceName] = conn
    return conn
}

func (c *Client) createConnection(serviceName string) (*grpc.ClientConn, error) {
    serviceConfig := c.config.Services[serviceName]
    
    opts := []grpc.DialOption{
        grpc.WithInsecure(), // Use TLS in production
        grpc.WithKeepaliveParams(keepalive.ClientParameters{
            Time:                10 * time.Second,
            Timeout:             3 * time.Second,
            PermitWithoutStream: true,
        }),
        grpc.WithUnaryInterceptor(c.unaryInterceptor),
    }
    
    return grpc.Dial(serviceConfig.Address, opts...)
}

func (c *Client) unaryInterceptor(
    ctx context.Context,
    method string,
    req, reply interface{},
    cc *grpc.ClientConn,
    invoker grpc.UnaryInvoker,
    opts ...grpc.CallOption,
) error {
    start := time.Now()
    
    // Circuit breaker check
    serviceName := c.extractServiceName(method)
    if cb := c.circuitBreakers[serviceName]; cb != nil {
        if !cb.Allow() {
            return errors.New("circuit breaker open")
        }
    }
    
    // Add timeout to context
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    
    // Make the call
    err := invoker(ctx, method, req, reply, cc, opts...)
    
    // Record metrics
    duration := time.Since(start)
    c.metrics.RecordRequest(method, err, duration)
    
    // Update circuit breaker
    if cb := c.circuitBreakers[serviceName]; cb != nil {
        if err != nil {
            cb.RecordFailure()
        } else {
            cb.RecordSuccess()
        }
    }
    
    return err
}
```

### 5. Redis Client Service (`internal/services/redis/redis_client.go`)

Provides caching, session management, and pub/sub functionality:

```go
type Client struct {
    client redis.UniversalClient
    pubsub *redis.PubSub
    config *config.RedisConfig
    logger *logging.Logger
}

func NewClient(cfg *config.RedisConfig, logger *logging.Logger) (*Client, error) {
    opts := &redis.UniversalOptions{
        Addrs:        []string{cfg.Address},
        Password:     cfg.Password,
        DB:           cfg.DB,
        PoolSize:     cfg.PoolSize,
        MaxRetries:   cfg.MaxRetries,
        DialTimeout:  cfg.DialTimeout,
        ReadTimeout:  cfg.ReadTimeout,
        WriteTimeout: cfg.WriteTimeout,
    }
    
    client := redis.NewUniversalClient(opts)
    
    // Test connection
    if err := client.Ping(context.Background()).Err(); err != nil {
        return nil, fmt.Errorf("failed to connect to Redis: %w", err)
    }
    
    return &Client{
        client: client,
        config: cfg,
        logger: logger,
    }, nil
}

func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
    start := time.Now()
    defer func() {
        c.logger.Debug("Redis GET operation", 
            "key", key, "duration", time.Since(start))
    }()
    
    result, err := c.client.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil, ErrKeyNotFound
    }
    return result, err
}

func (c *Client) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
    start := time.Now()
    defer func() {
        c.logger.Debug("Redis SET operation", 
            "key", key, "ttl", ttl, "duration", time.Since(start))
    }()
    
    return c.client.Set(ctx, key, value, ttl).Err()
}

func (c *Client) Publish(ctx context.Context, channel string, message interface{}) error {
    data, err := json.Marshal(message)
    if err != nil {
        return fmt.Errorf("failed to marshal message: %w", err)
    }
    
    return c.client.Publish(ctx, channel, data).Err()
}

func (c *Client) Subscribe(ctx context.Context, channels ...string) *redis.PubSub {
    return c.client.Subscribe(ctx, channels...)
}
```

### 6. WebSocket Handler (`api/ws/handler.go`)

Manages real-time WebSocket connections with Redis Pub/Sub integration:

```go
type Handler struct {
    upgrader    websocket.Upgrader
    redisClient *redis.Client
    connManager *ConnectionManager
    logger      *logging.Logger
}

func (h *Handler) HandleConnection(c *gin.Context) {
    // Get user claims from auth middleware
    claims, exists := c.Get("user_claims")
    if !exists {
        c.JSON(401, gin.H{"error": "Authentication required"})
        return
    }
    
    userClaims := claims.(*auth.Claims)
    
    // Upgrade HTTP connection to WebSocket
    conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        h.logger.Error("Failed to upgrade WebSocket connection", "error", err)
        return
    }
    defer conn.Close()
    
    // Register connection
    connID := h.connManager.Register(userClaims.UserID, conn)
    defer h.connManager.Unregister(connID)
    
    // Subscribe to user-specific channel
    userChannel := fmt.Sprintf("notifications:%s", userClaims.UserID)
    pubsub := h.redisClient.Subscribe(context.Background(), userChannel)
    defer pubsub.Close()
    
    // Handle messages
    go h.handlePubSubMessages(conn, pubsub)
    
    // Handle WebSocket messages from client
    h.handleClientMessages(conn, userClaims)
}

func (h *Handler) handlePubSubMessages(conn *websocket.Conn, pubsub *redis.PubSub) {
    ch := pubsub.Channel()
    for msg := range ch {
        var notification Notification
        if err := json.Unmarshal([]byte(msg.Payload), &notification); err != nil {
            h.logger.Error("Failed to unmarshal notification", "error", err)
            continue
        }
        
        if err := conn.WriteJSON(notification); err != nil {
            h.logger.Error("Failed to send WebSocket message", "error", err)
            break
        }
    }
}

func (h *Handler) handleClientMessages(conn *websocket.Conn, claims *auth.Claims) {
    for {
        var msg ClientMessage
        if err := conn.ReadJSON(&msg); err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                h.logger.Error("WebSocket error", "error", err)
            }
            break
        }
        
        // Handle different message types
        switch msg.Type {
        case "subscribe":
            h.handleSubscribe(conn, claims, msg.Channel)
        case "unsubscribe":
            h.handleUnsubscribe(conn, claims, msg.Channel)
        case "ping":
            h.handlePing(conn)
        }
    }
}

type ConnectionManager struct {
    connections map[string]*Connection
    userConns   map[string][]string
    mutex       sync.RWMutex
}

type Connection struct {
    ID     string
    UserID string
    Conn   *websocket.Conn
    Channels []string
}

func (cm *ConnectionManager) Register(userID string, conn *websocket.Conn) string {
    cm.mutex.Lock()
    defer cm.mutex.Unlock()
    
    connID := generateConnectionID()
    connection := &Connection{
        ID:     connID,
        UserID: userID,
        Conn:   conn,
        Channels: []string{},
    }
    
    cm.connections[connID] = connection
    cm.userConns[userID] = append(cm.userConns[userID], connID)
    
    return connID
}
```

## Development Workflow

### Code Style and Standards

The project follows Go best practices and conventions:

1. **Naming Conventions**
   - Use camelCase for variables and functions
   - Use PascalCase for exported types and functions
   - Use descriptive names that explain purpose
   - Avoid abbreviations unless they're well-known

2. **Package Organization**
   - Keep packages focused on a single responsibility
   - Use internal packages for code that shouldn't be imported
   - Group related functionality together

3. **Error Handling**
   - Always handle errors explicitly
   - Use wrapped errors for context: `fmt.Errorf("operation failed: %w", err)`
   - Log errors at the appropriate level
   - Return structured errors to clients

4. **Documentation**
   - Document all exported functions and types
   - Use godoc format for documentation
   - Include examples for complex functionality
   - Keep documentation up to date

### Git Workflow

1. **Branch Naming**
   - `feature/description` - New features
   - `bugfix/description` - Bug fixes
   - `hotfix/description` - Critical fixes
   - `refactor/description` - Code refactoring

2. **Commit Messages**
   ```
   type(scope): description
   
   Longer description if needed
   
   Fixes #123
   ```
   
   Types: feat, fix, docs, style, refactor, test, chore

3. **Pull Request Process**
   - Create feature branch from main
   - Make changes with tests
   - Run full test suite
   - Create pull request with description
   - Address review feedback
   - Merge after approval

### Code Generation

The project uses code generation for several components:

1. **Protocol Buffers**
```bash
# Generate Go code from .proto files
make proto-gen

# Or manually
protoc --go_out=. --go-grpc_out=. proto/**/*.proto
```

2. **GraphQL Schema**
```bash
# Generate GraphQL resolvers
go generate ./api/graphql/...
```

3. **Mocks for Testing**
```bash
# Generate mocks using mockery
mockery --all --output=test/mocks
```

### Build and Release

1. **Local Build**
```bash
# Build binary
make build

# Build with version info
make build VERSION=v1.0.0

# Cross-compile for different platforms
make build-all
```

2. **Docker Build**
```bash
# Build Docker image
make docker-build

# Build and push to registry
make docker-push TAG=v1.0.0
```

3. **Release Process**
```bash
# Create release
make release VERSION=v1.0.0

# This will:
# - Run all tests
# - Build binaries for all platforms
# - Create Docker images
# - Generate changelog
# - Create Git tag
```

## Testing Guide

### Test Structure

The project uses a comprehensive testing strategy:

```
test/
├── unit/              # Unit tests (alongside source code)
├── integration/       # Integration tests
├── load/             # Load and performance tests
├── mocks/            # Generated mocks
└── fixtures/         # Test data and fixtures
```

### Unit Testing

Unit tests are placed alongside source code with `_test.go` suffix:

```go
// auth_handler_test.go
func TestAuthHandler_Login(t *testing.T) {
    tests := []struct {
        name           string
        request        LoginRequest
        mockSetup      func(*mocks.MockGRPCClient, *mocks.MockRedisClient)
        expectedStatus int
        expectedBody   string
    }{
        {
            name: "successful login",
            request: LoginRequest{
                Email:    "user@example.com",
                Password: "password123",
            },
            mockSetup: func(grpc *mocks.MockGRPCClient, redis *mocks.MockRedisClient) {
                grpc.On("Login", mock.Anything, mock.Anything).Return(&authpb.LoginResponse{
                    Success: true,
                    Data: &authpb.AuthData{
                        User: &authpb.User{
                            Id:    "123",
                            Email: "user@example.com",
                        },
                        AccessToken: "token123",
                    },
                }, nil)
                
                redis.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(nil)
            },
            expectedStatus: 200,
        },
        {
            name: "invalid credentials",
            request: LoginRequest{
                Email:    "user@example.com",
                Password: "wrongpassword",
            },
            mockSetup: func(grpc *mocks.MockGRPCClient, redis *mocks.MockRedisClient) {
                grpc.On("Login", mock.Anything, mock.Anything).Return(nil, 
                    status.Error(codes.Unauthenticated, "invalid credentials"))
            },
            expectedStatus: 401,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup mocks
            mockGRPC := &mocks.MockGRPCClient{}
            mockRedis := &mocks.MockRedisClient{}
            tt.mockSetup(mockGRPC, mockRedis)
            
            // Create handler
            handler := &AuthHandler{
                grpcClient:  mockGRPC,
                redisClient: mockRedis,
            }
            
            // Create test request
            body, _ := json.Marshal(tt.request)
            req := httptest.NewRequest("POST", "/auth/login/", bytes.NewBuffer(body))
            req.Header.Set("Content-Type", "application/json")
            
            // Create response recorder
            w := httptest.NewRecorder()
            c, _ := gin.CreateTestContext(w)
            c.Request = req
            
            // Execute handler
            handler.Login(c)
            
            // Assert results
            assert.Equal(t, tt.expectedStatus, w.Code)
            
            // Verify mocks
            mockGRPC.AssertExpectations(t)
            mockRedis.AssertExpectations(t)
        })
    }
}
```

### Integration Testing

Integration tests verify complete request flows:

```go
// integration_test.go
func TestAuthenticationFlow(t *testing.T) {
    // Setup test server
    server := setupTestServer(t)
    defer server.Close()
    
    // Test user registration
    registerResp := testRegister(t, server, RegisterRequest{
        FirstName: "John",
        LastName:  "Doe",
        Email:     "john@example.com",
        Password:  "password123",
    })
    assert.True(t, registerResp.Success)
    
    // Test login
    loginResp := testLogin(t, server, LoginRequest{
        Email:    "john@example.com",
        Password: "password123",
    })
    assert.True(t, loginResp.Success)
    assert.NotEmpty(t, loginResp.Data.AccessToken)
    
    // Test protected endpoint
    userResp := testGetCurrentUser(t, server, loginResp.Data.AccessToken)
    assert.True(t, userResp.Success)
    assert.Equal(t, "john@example.com", userResp.Data.Email)
    
    // Test logout
    logoutResp := testLogout(t, server, loginResp.Data.AccessToken)
    assert.True(t, logoutResp.Success)
    
    // Verify token is invalidated
    userResp2 := testGetCurrentUser(t, server, loginResp.Data.AccessToken)
    assert.False(t, userResp2.Success)
}

func setupTestServer(t *testing.T) *httptest.Server {
    // Create test configuration
    cfg := &config.Config{
        Server: config.ServerConfig{
            Port: 0, // Random port
        },
        // ... other test config
    }
    
    // Create test container with mocked dependencies
    container := createTestContainer(cfg)
    
    // Create server
    server := server.New(cfg, container)
    
    return httptest.NewServer(server.Handler())
}
```

### Load Testing

Performance tests verify scalability requirements:

```go
// load_test.go
func TestLoadPerformance(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }
    
    server := setupTestServer(t)
    defer server.Close()
    
    // Test parameters
    concurrency := 100
    requests := 1000
    duration := 30 * time.Second
    
    // Create load test
    results := runLoadTest(LoadTestConfig{
        URL:         server.URL + "/auth/login/",
        Method:      "POST",
        Body:        `{"email":"user@example.com","password":"password123"}`,
        Concurrency: concurrency,
        Requests:    requests,
        Duration:    duration,
    })
    
    // Assert performance requirements
    assert.Less(t, results.ErrorRate, 0.01, "Error rate should be < 1%")
    assert.Less(t, results.AvgResponseTime, 100*time.Millisecond, "Avg response time should be < 100ms")
    assert.Less(t, results.P95ResponseTime, 200*time.Millisecond, "P95 response time should be < 200ms")
    
    t.Logf("Load test results:")
    t.Logf("  Total requests: %d", results.TotalRequests)
    t.Logf("  Successful requests: %d", results.SuccessfulRequests)
    t.Logf("  Error rate: %.2f%%", results.ErrorRate*100)
    t.Logf("  Avg response time: %v", results.AvgResponseTime)
    t.Logf("  P95 response time: %v", results.P95ResponseTime)
    t.Logf("  Requests/second: %.2f", results.RequestsPerSecond)
}
```

### Test Commands

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run only unit tests
make test-unit

# Run only integration tests
make test-integration

# Run load tests
make test-load

# Run tests with race detection
make test-race

# Generate test coverage report
make coverage-html

# Run specific test
go test -v ./api/rest -run TestAuthHandler_Login

# Run tests with verbose output
go test -v ./...

# Run tests and generate coverage profile
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Benchmarking

Benchmark critical code paths:

```go
func BenchmarkAuthMiddleware_ValidateJWT(b *testing.B) {
    middleware := setupAuthMiddleware()
    token := generateValidToken()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := middleware.validateToken(token)
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkRedisClient_Get(b *testing.B) {
    client := setupRedisClient()
    key := "test-key"
    value := []byte("test-value")
    
    // Setup
    client.Set(context.Background(), key, value, time.Hour)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := client.Get(context.Background(), key)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Configuration Management

### Configuration Structure

Configuration is managed through a hierarchical structure:

```go
type Config struct {
    Server    ServerConfig    `yaml:"server" env:"SERVER"`
    Database  DatabaseConfig  `yaml:"database" env:"DATABASE"`
    Redis     RedisConfig     `yaml:"redis" env:"REDIS"`
    Kafka     KafkaConfig     `yaml:"kafka" env:"KAFKA"`
    GRPC      GRPCConfig      `yaml:"grpc" env:"GRPC"`
    JWT       JWTConfig       `yaml:"jwt" env:"JWT"`
    Logging   LoggingConfig   `yaml:"logging" env:"LOGGING"`
}

type ServerConfig struct {
    Port            int           `yaml:"port" env:"PORT" default:"8080"`
    Host            string        `yaml:"host" env:"HOST" default:"0.0.0.0"`
    ReadTimeout     time.Duration `yaml:"read_timeout" env:"READ_TIMEOUT" default:"30s"`
    WriteTimeout    time.Duration `yaml:"write_timeout" env:"WRITE_TIMEOUT" default:"30s"`
    ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"SHUTDOWN_TIMEOUT" default:"10s"`
    CORS            CORSConfig    `yaml:"cors"`
    RateLimit       RateLimitConfig `yaml:"rate_limit"`
}

type GRPCConfig struct {
    Services map[string]ServiceConfig `yaml:"services"`
}

type ServiceConfig struct {
    Address     string        `yaml:"address" env:"ADDRESS"`
    Timeout     time.Duration `yaml:"timeout" env:"TIMEOUT" default:"10s"`
    MaxRetries  int           `yaml:"max_retries" env:"MAX_RETRIES" default:"3"`
    PoolSize    int           `yaml:"pool_size" env:"POOL_SIZE" default:"10"`
}
```

### Configuration Loading

Configuration is loaded from multiple sources with precedence:

1. Default values (struct tags)
2. Configuration file (YAML/JSON)
3. Environment variables
4. Command line flags

```go
func LoadConfig() (*Config, error) {
    cfg := &Config{}
    
    // Load defaults
    if err := setDefaults(cfg); err != nil {
        return nil, err
    }
    
    // Load from file
    if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
        if err := loadFromFile(cfg, configFile); err != nil {
            return nil, err
        }
    } else {
        // Try default locations
        for _, path := range []string{"config.yaml", "/etc/gateway/config.yaml"} {
            if _, err := os.Stat(path); err == nil {
                if err := loadFromFile(cfg, path); err != nil {
                    return nil, err
                }
                break
            }
        }
    }
    
    // Load from environment
    if err := loadFromEnv(cfg); err != nil {
        return nil, err
    }
    
    // Validate configuration
    if err := validateConfig(cfg); err != nil {
        return nil, err
    }
    
    return cfg, nil
}

func loadFromFile(cfg *Config, filename string) error {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return err
    }
    
    switch filepath.Ext(filename) {
    case ".yaml", ".yml":
        return yaml.Unmarshal(data, cfg)
    case ".json":
        return json.Unmarshal(data, cfg)
    default:
        return fmt.Errorf("unsupported config file format: %s", filename)
    }
}

func loadFromEnv(cfg *Config) error {
    return envconfig.Process("", cfg)
}
```

### Environment Variables

All configuration can be overridden using environment variables:

```bash
# Server configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0
SERVER_READ_TIMEOUT=30s

# gRPC services
GRPC_SERVICES_AUTH_ADDRESS=auth-service:50051
GRPC_SERVICES_AUTH_TIMEOUT=10s
GRPC_SERVICES_CRM_ADDRESS=crm-service:50052

# Redis configuration
REDIS_ADDRESS=redis:6379
REDIS_PASSWORD=secret
REDIS_DB=0
REDIS_POOL_SIZE=10

# Kafka configuration
KAFKA_BROKERS=kafka1:9092,kafka2:9092
KAFKA_CLIENT_ID=api-gateway
KAFKA_MAX_RETRIES=3

# JWT configuration
JWT_PUBLIC_KEY_PATH=/etc/certs/jwt-public.pem
JWT_JWKS_URL=https://auth-service/jwks
JWT_CACHE_TTL=1h

# Logging configuration
LOGGING_LEVEL=info
LOGGING_ELASTICSEARCH_ADDRESSES=http://elasticsearch:9200
LOGGING_ELASTICSEARCH_INDEX=api-gateway-logs
```

### Configuration Validation

Configuration is validated at startup:

```go
func validateConfig(cfg *Config) error {
    var errors []string
    
    // Validate server config
    if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
        errors = append(errors, "server.port must be between 1 and 65535")
    }
    
    // Validate gRPC services
    for name, service := range cfg.GRPC.Services {
        if service.Address == "" {
            errors = append(errors, fmt.Sprintf("grpc.services.%s.address is required", name))
        }
        if service.Timeout <= 0 {
            errors = append(errors, fmt.Sprintf("grpc.services.%s.timeout must be positive", name))
        }
    }
    
    // Validate Redis config
    if cfg.Redis.Address == "" {
        errors = append(errors, "redis.address is required")
    }
    
    // Validate JWT config
    if cfg.JWT.PublicKeyPath == "" && cfg.JWT.JWKSUrl == "" {
        errors = append(errors, "either jwt.public_key_path or jwt.jwks_url must be specified")
    }
    
    if len(errors) > 0 {
        return fmt.Errorf("configuration validation failed:\n  %s", strings.Join(errors, "\n  "))
    }
    
    return nil
}
```

## Deployment Guide

### Docker Deployment

#### Multi-stage Dockerfile

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o gateway cmd/server/main.go

# Runtime stage
FROM scratch

# Copy certificates and timezone data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary
COPY --from=builder /app/gateway /gateway

# Copy configuration
COPY --from=builder /app/config.yaml /config.yaml

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/gateway", "healthcheck"]

# Run as non-root user
USER 65534:65534

# Start application
ENTRYPOINT ["/gateway"]
```

#### Docker Compose for Development

```yaml
version: '3.8'

services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      - LOG_LEVEL=debug
      - REDIS_ADDRESS=redis:6379
      - KAFKA_BROKERS=kafka:9092
      - GRPC_SERVICES_AUTH_ADDRESS=auth-service:50051
    depends_on:
      - redis
      - kafka
      - auth-service
    volumes:
      - ./config.yaml:/config.yaml
      - ./certs:/etc/certs
    networks:
      - gateway-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - gateway-network

  kafka:
    image: confluentinc/cp-kafka:latest
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    depends_on:
      - zookeeper
    networks:
      - gateway-network

  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    networks:
      - gateway-network

  auth-service:
    image: auth-service:latest
    ports:
      - "50051:50051"
    networks:
      - gateway-network

volumes:
  redis-data:

networks:
  gateway-network:
    driver: bridge
```

### Kubernetes Deployment

#### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  labels:
    app: api-gateway
    version: v1.0.0
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
        version: v1.0.0
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: api-gateway
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
      containers:
      - name: gateway
        image: api-gateway:v1.0.0
        imagePullPolicy: IfNotPresent
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        env:
        - name: SERVER_PORT
          value: "8080"
        - name: LOG_LEVEL
          value: "info"
        - name: REDIS_ADDRESS
          value: "redis-service:6379"
        - name: KAFKA_BROKERS
          value: "kafka-service:9092"
        - name: GRPC_SERVICES_AUTH_ADDRESS
          value: "auth-service:50051"
        - name: JWT_PUBLIC_KEY_PATH
          value: "/etc/certs/jwt-public.pem"
        envFrom:
        - configMapRef:
            name: api-gateway-config
        - secretRef:
            name: api-gateway-secrets
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        volumeMounts:
        - name: config
          mountPath: /config.yaml
          subPath: config.yaml
          readOnly: true
        - name: certs
          mountPath: /etc/certs
          readOnly: true
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: api-gateway-config
      - name: certs
        secret:
          secretName: api-gateway-certs
      terminationGracePeriodSeconds: 30
```

#### Service Manifest

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-service
  labels:
    app: api-gateway
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app: api-gateway
---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-headless
  labels:
    app: api-gateway
spec:
  type: ClusterIP
  clusterIP: None
  ports:
  - port: 8080
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app: api-gateway
```

#### ConfigMap and Secrets

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-gateway-config
data:
  config.yaml: |
    server:
      port: 8080
      host: "0.0.0.0"
      read_timeout: "30s"
      write_timeout: "30s"
      shutdown_timeout: "10s"
      cors:
        allowed_origins:
          - "https://app.erp-system.com"
        allowed_methods:
          - "GET"
          - "POST"
          - "PUT"
          - "DELETE"
        allow_credentials: true
    
    grpc:
      services:
        auth:
          address: "auth-service:50051"
          timeout: "10s"
          max_retries: 3
        crm:
          address: "crm-service:50052"
          timeout: "10s"
          max_retries: 3
    
    redis:
      address: "redis-service:6379"
      db: 0
      pool_size: 10
      max_retries: 3
    
    kafka:
      brokers:
        - "kafka-service:9092"
      client_id: "api-gateway"
      max_retries: 3
    
    logging:
      level: "info"
      elasticsearch:
        addresses:
          - "http://elasticsearch:9200"
        index: "api-gateway-logs"
        batch_size: 100
        flush_interval: "5s"

---
apiVersion: v1
kind: Secret
metadata:
  name: api-gateway-secrets
type: Opaque
data:
  REDIS_PASSWORD: <base64-encoded-password>
  KAFKA_SASL_PASSWORD: <base64-encoded-password>

---
apiVersion: v1
kind: Secret
metadata:
  name: api-gateway-certs
type: Opaque
data:
  jwt-public.pem: <base64-encoded-public-key>
  tls.crt: <base64-encoded-certificate>
  tls.key: <base64-encoded-private-key>
```

#### HorizontalPodAutoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

### Monitoring and Observability

#### ServiceMonitor for Prometheus

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api-gateway
  labels:
    app: api-gateway
spec:
  selector:
    matchLabels:
      app: api-gateway
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
```

#### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "API Gateway Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"4..|5..\"}[5m]) / rate(http_requests_total[5m])",
            "legendFormat": "Error Rate"
          }
        ]
      }
    ]
  }
}
```

## Contributing Guidelines

### Code Review Process

1. **Pre-Review Checklist**
   - [ ] All tests pass
   - [ ] Code coverage meets requirements (>90%)
   - [ ] Documentation is updated
   - [ ] No security vulnerabilities
   - [ ] Performance impact assessed

2. **Review Criteria**
   - Code follows project conventions
   - Logic is clear and well-documented
   - Error handling is appropriate
   - Tests are comprehensive
   - No code duplication

3. **Review Process**
   - Create pull request with clear description
   - Assign reviewers (minimum 2)
   - Address all feedback
   - Ensure CI/CD passes
   - Merge after approval

### Security Guidelines

1. **Input Validation**
   - Validate all user inputs
   - Use parameterized queries
   - Sanitize output data
   - Implement rate limiting

2. **Authentication & Authorization**
   - Use strong JWT signatures
   - Implement proper RBAC
   - Validate permissions on every request
   - Log security events

3. **Data Protection**
   - Encrypt sensitive data
   - Use HTTPS for all communication
   - Implement proper session management
   - Follow OWASP guidelines

### Performance Guidelines

1. **Optimization Principles**
   - Profile before optimizing
   - Use appropriate data structures
   - Implement caching strategically
   - Minimize memory allocations

2. **Monitoring**
   - Track key metrics
   - Set up alerting
   - Regular performance reviews
   - Load testing in CI/CD

## Troubleshooting

### Common Issues

#### High Memory Usage

**Symptoms**: OOM kills, high memory metrics
**Causes**: Memory leaks, large object retention, inefficient caching
**Solutions**:
```bash
# Check memory usage
kubectl top pods -l app=api-gateway

# Get memory profile
curl http://gateway:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Check for goroutine leaks
curl http://gateway:8080/debug/pprof/goroutine > goroutine.prof
go tool pprof goroutine.prof
```

#### High CPU Usage

**Symptoms**: High CPU metrics, slow responses
**Causes**: Inefficient algorithms, excessive logging, hot loops
**Solutions**:
```bash
# Get CPU profile
curl http://gateway:8080/debug/pprof/profile > cpu.prof
go tool pprof cpu.prof

# Check for CPU-intensive operations
go tool pprof -top cpu.prof
go tool pprof -web cpu.prof
```

#### Database Connection Issues

**Symptoms**: Connection timeouts, pool exhaustion
**Causes**: Connection leaks, improper pool configuration
**Solutions**:
```bash
# Check connection pool metrics
curl http://gateway:8080/metrics | grep db_connections

# Verify database connectivity
kubectl exec -it api-gateway-pod -- /gateway healthcheck

# Check database logs
kubectl logs -f deployment/database
```

### Debugging Tools

#### Application Debugging

```bash
# Enable debug logging
kubectl set env deployment/api-gateway LOG_LEVEL=debug

# Get application logs
kubectl logs -f deployment/api-gateway

# Execute commands in pod
kubectl exec -it api-gateway-pod -- /bin/sh

# Port forward for local debugging
kubectl port-forward deployment/api-gateway 8080:8080
```

#### Performance Debugging

```bash
# Get performance metrics
curl http://localhost:8080/metrics

# CPU profiling
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# Memory profiling
curl http://localhost:8080/debug/pprof/heap > mem.prof
go tool pprof mem.prof

# Goroutine analysis
curl http://localhost:8080/debug/pprof/goroutine > goroutine.prof
go tool pprof goroutine.prof

# Trace analysis
curl http://localhost:8080/debug/pprof/trace?seconds=10 > trace.out
go tool trace trace.out
```

#### Network Debugging

```bash
# Test connectivity to services
kubectl exec -it api-gateway-pod -- nc -zv auth-service 50051
kubectl exec -it api-gateway-pod -- nc -zv redis-service 6379

# Check DNS resolution
kubectl exec -it api-gateway-pod -- nslookup auth-service

# Network policy debugging
kubectl describe networkpolicy api-gateway-netpol
```

### Log Analysis

#### Error Pattern Analysis

```bash
# Find authentication errors
kubectl logs deployment/api-gateway | grep "authentication failed"

# Find high response times
kubectl logs deployment/api-gateway | jq 'select(.duration_ms > 1000)'

# Find gRPC errors
kubectl logs deployment/api-gateway | grep "grpc error"

# Analyze error rates by endpoint
kubectl logs deployment/api-gateway | jq -r '[.path, .status_code] | @csv' | sort | uniq -c
```

#### Performance Analysis

```bash
# Response time analysis
kubectl logs deployment/api-gateway | jq '.duration_ms' | sort -n

# Request rate analysis
kubectl logs deployment/api-gateway | jq -r '.timestamp' | cut -c1-16 | uniq -c

# Error rate by time
kubectl logs deployment/api-gateway | jq -r 'select(.status_code >= 400) | .timestamp' | cut -c1-13 | uniq -c
```

---

This developer documentation provides comprehensive guidance for working with the ERP API Gateway codebase. It covers everything from initial setup to advanced debugging techniques, ensuring developers can effectively contribute to and maintain the system.