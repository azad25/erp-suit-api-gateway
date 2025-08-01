# REST API Handlers

This package implements REST API handlers for the Go API Gateway, providing HTTP endpoints that translate requests to gRPC calls to backend services.

## Features

- **Authentication Endpoints**: Login, register, logout, refresh token, and current user
- **Backward Compatibility**: Maintains the same response format as the existing Django API
- **Response Caching**: Caches user profiles and permissions for improved performance
- **Event Publishing**: Publishes business events to Kafka for user actions
- **Comprehensive Testing**: Unit tests with >90% coverage using mocks

## Architecture

### Handler Structure

```go
type AuthHandler struct {
    grpcClient     GRPCClientInterface
    cacheService   interfaces.CacheService
    eventPublisher interfaces.EventPublisher
    logger         interfaces.SimpleLogger
}
```

### Request Flow

1. **HTTP Request** → REST Handler
2. **Validation** → Gin binding validation
3. **gRPC Translation** → Convert HTTP request to gRPC request
4. **Backend Call** → Call appropriate gRPC service
5. **Response Translation** → Convert gRPC response to HTTP response
6. **Caching** → Cache appropriate responses (user profiles, permissions)
7. **Event Publishing** → Publish business events to Kafka
8. **HTTP Response** → Return standardized JSON response

## API Endpoints

### Authentication Endpoints

#### POST /auth/login/
Authenticates a user and returns access/refresh tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "remember_me": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "user-123",
      "first_name": "John",
      "last_name": "Doe",
      "email": "user@example.com",
      "email_verified_at": "2023-01-01T00:00:00Z",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    },
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "expires_in": 3600
  }
}
```

#### POST /auth/register/
Registers a new user account.

**Request:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "user@example.com",
  "password": "password123",
  "password_confirmation": "password123"
}
```

**Response:** Same as login response

#### POST /auth/logout/
Logs out the current user and revokes their token.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

#### POST /auth/refresh/
Refreshes an access token using a refresh token.

**Request:**
```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "expires_in": 3600
  }
}
```

#### GET /auth/me/
Returns the current authenticated user's information.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "success": true,
  "message": "User profile retrieved",
  "data": {
    "id": "user-123",
    "first_name": "John",
    "last_name": "Doe",
    "email": "user@example.com",
    "email_verified_at": "2023-01-01T00:00:00Z",
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z"
  }
}
```

## Error Handling

All endpoints return errors in a consistent format:

```json
{
  "success": false,
  "message": "Error description",
  "errors": {
    "field_name": ["Field-specific error message"]
  }
}
```

### HTTP Status Codes

- `200 OK` - Successful request
- `201 Created` - Successful registration
- `400 Bad Request` - Validation errors
- `401 Unauthorized` - Authentication failed
- `403 Forbidden` - Authorization failed
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Backend service unavailable

## Caching Strategy

### Cached Data
- **User Profiles** - TTL: 15 minutes
- **User Permissions** - TTL: 10 minutes
- **User Roles** - TTL: 10 minutes

### Cache Keys
```go
const (
    CacheKeyUserProfile     = "user_profile:%s"
    CacheKeyUserPermissions = "user_permissions:%s"
    CacheKeyUserRoles       = "user_roles:%s"
)
```

### Cache Behavior
- **Cache Hit** - Return cached data immediately
- **Cache Miss** - Fetch from gRPC service, cache result, return data
- **Cache Invalidation** - Clear cache on logout or user updates

## Event Publishing

### Published Events

#### User Login
```json
{
  "id": "event-uuid",
  "type": "user.logged_in",
  "user_id": "user-123",
  "data": {
    "email": "user@example.com",
    "login_time": "2023-01-01T00:00:00Z",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0..."
  },
  "timestamp": "2023-01-01T00:00:00Z",
  "correlation_id": "correlation-uuid",
  "source": "api-gateway",
  "version": "1.0"
}
```

#### User Registration
```json
{
  "id": "event-uuid",
  "type": "user.registered",
  "user_id": "user-123",
  "data": {
    "email": "user@example.com",
    "registration_time": "2023-01-01T00:00:00Z",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0..."
  },
  "timestamp": "2023-01-01T00:00:00Z",
  "correlation_id": "correlation-uuid",
  "source": "api-gateway",
  "version": "1.0"
}
```

#### User Logout
```json
{
  "id": "event-uuid",
  "type": "user.logged_out",
  "user_id": "user-123",
  "data": {
    "logout_time": "2023-01-01T00:00:00Z",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0..."
  },
  "timestamp": "2023-01-01T00:00:00Z",
  "correlation_id": "correlation-uuid",
  "source": "api-gateway",
  "version": "1.0"
}
```

#### Token Refresh
```json
{
  "id": "event-uuid",
  "type": "user.token_refreshed",
  "user_id": "user-123",
  "data": {
    "refresh_time": "2023-01-01T00:00:00Z",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0..."
  },
  "timestamp": "2023-01-01T00:00:00Z",
  "correlation_id": "correlation-uuid",
  "source": "api-gateway",
  "version": "1.0"
}
```

## Testing

### Running Tests
```bash
go test ./api/rest/... -v
```

### Test Coverage
```bash
go test ./api/rest/... -cover
```

### Mock Usage
The tests use comprehensive mocks for all external dependencies:
- `MockGRPCClient` - Mocks gRPC client interface
- `MockAuthServiceClient` - Mocks auth service gRPC client
- `MockCacheService` - Mocks Redis cache service
- `MockEventPublisher` - Mocks Kafka event publisher
- `MockLogger` - Mocks logging service

### Test Scenarios
- ✅ Successful login with valid credentials
- ✅ Login failure with invalid credentials
- ✅ Service unavailable scenarios
- ✅ Successful user registration
- ✅ Registration with password mismatch
- ✅ Current user retrieval (authenticated)
- ✅ Current user retrieval (unauthenticated)
- ✅ Helper method functionality
- ✅ Error conversion and response formatting

## Integration

### Router Setup
```go
import (
    "github.com/gin-gonic/gin"
    "erp-api-gateway/api/rest"
    "erp-api-gateway/internal/services/grpc_client"
)

func setupRoutes(
    router *gin.Engine,
    grpcClient *grpc_client.GRPCClient,
    cacheService interfaces.CacheService,
    eventPublisher interfaces.EventPublisher,
    logger interfaces.SimpleLogger,
) {
    config := &rest.RouterConfig{
        GRPCClient:     grpcClient,
        CacheService:   cacheService,
        EventPublisher: eventPublisher,
        Logger:         logger,
    }
    
    rest.SetupAuthRoutes(router, config)
}
```

### Middleware Integration
The handlers expect certain middleware to be applied:
- **Authentication Middleware** - Sets `user_id` in context for protected routes
- **CORS Middleware** - Handles cross-origin requests
- **Logging Middleware** - Adds request logging
- **Rate Limiting Middleware** - Prevents abuse

## Performance Considerations

### Response Caching
- User profiles are cached for 15 minutes
- Permissions and roles are cached for 10 minutes
- Cache keys include user ID for proper isolation

### Event Publishing
- Events are published asynchronously to avoid blocking requests
- Failed event publishing is logged but doesn't fail the request
- Correlation IDs are used for event tracing

### Error Handling
- gRPC errors are properly translated to HTTP status codes
- Service unavailable scenarios are handled gracefully
- Validation errors provide detailed field-level feedback

## Security Features

### Input Validation
- All request payloads are validated using Gin binding
- Email format validation
- Password strength requirements
- Required field validation

### Token Handling
- JWT tokens are extracted from Authorization header
- Tokens are validated before processing protected requests
- Token revocation is handled through the auth service

### Error Information
- Error messages don't leak sensitive information
- Stack traces are logged but not returned to clients
- User enumeration is prevented through consistent error messages

## Future Enhancements

### Planned Features
- [ ] Rate limiting per user/IP
- [ ] Request/response compression
- [ ] API versioning support
- [ ] OpenAPI/Swagger documentation
- [ ] Metrics collection (Prometheus)
- [ ] Distributed tracing integration

### Extensibility
The handler architecture is designed to be easily extensible:
- New endpoints can be added by implementing additional handler methods
- New services can be integrated by extending the gRPC client interface
- Additional caching strategies can be implemented
- Custom event types can be added for new business events