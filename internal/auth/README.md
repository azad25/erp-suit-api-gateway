# JWT Authentication and Validation

This package provides JWT token validation and authentication middleware for the Go API Gateway.

## Features

- **RS256 JWT Token Validation**: Validates JWT tokens using RS256 signature verification
- **JWKS Support**: Supports JSON Web Key Set (JWKS) for key rotation
- **Token Caching**: Caches validated tokens in Redis for improved performance
- **Claims Extraction**: Extracts user claims including user_id, roles, and permissions
- **Middleware Integration**: Provides Gin middleware for easy integration
- **Role-Based Access Control**: Helper functions for role and permission checking

## Components

### JWT Validator

The `JWTValidator` handles token validation and JWKS management:

```go
// Create JWT validator
jwtValidator := auth.NewJWTValidator(&config.JWT{
    JWKSUrl:   "https://auth-service/.well-known/jwks.json",
    Algorithm: "RS256",
    Issuer:    "erp-auth-service",
    CacheTTL:  time.Hour,
}, redisCache)

// Validate a token
claims, err := jwtValidator.ValidateToken(tokenString)
if err != nil {
    // Handle validation error
}
```

### Authentication Middleware

The authentication middleware provides several middleware functions:

```go
// Create authentication middleware
authMiddleware := middleware.NewAuthMiddleware(jwtValidator, redisCache)

// Require authentication
router.Use(authMiddleware.RequireAuth())

// Optional authentication
router.Use(authMiddleware.OptionalJWT())

// Just validate JWT (without claims extraction)
router.Use(authMiddleware.ValidateJWT())

// Extract claims (use after ValidateJWT)
router.Use(authMiddleware.ExtractClaims())
```

## Usage Examples

### Basic Protected Endpoint

```go
router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
    userID, _ := middleware.GetUserID(c)
    c.JSON(http.StatusOK, gin.H{
        "message": "Hello " + userID,
    })
})
```

### Role-Based Access Control

```go
router.GET("/admin", authMiddleware.RequireAuth(), func(c *gin.Context) {
    if !middleware.HasRole(c, "admin") {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "Admin role required",
        })
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "Admin access granted",
    })
})
```

### Permission-Based Access Control

```go
router.POST("/documents", authMiddleware.RequireAuth(), func(c *gin.Context) {
    if !middleware.HasPermission(c, "write") {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "Write permission required",
        })
        return
    }
    
    // Create document
    c.JSON(http.StatusCreated, gin.H{
        "message": "Document created",
    })
})
```

### Optional Authentication

```go
router.GET("/profile", authMiddleware.OptionalJWT(), func(c *gin.Context) {
    if middleware.IsAuthenticated(c) {
        userID, _ := middleware.GetUserID(c)
        c.JSON(http.StatusOK, gin.H{
            "user_id": userID,
            "type": "authenticated",
        })
    } else {
        c.JSON(http.StatusOK, gin.H{
            "type": "anonymous",
        })
    }
})
```

### Multiple Roles/Permissions

```go
// Require any of the specified roles
router.GET("/reports", authMiddleware.RequireAuth(), func(c *gin.Context) {
    if !middleware.HasAnyRole(c, "admin", "manager", "analyst") {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "Admin, manager, or analyst role required",
        })
        return
    }
    
    // Return reports
})

// Require all specified permissions
router.DELETE("/documents/:id", authMiddleware.RequireAuth(), func(c *gin.Context) {
    if !middleware.HasAllPermissions(c, "write", "delete") {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "Both write and delete permissions required",
        })
        return
    }
    
    // Delete document
})
```

## Helper Functions

The middleware provides several helper functions to extract user information:

```go
// Get user claims
claims, exists := middleware.GetUserClaims(c)

// Get user ID
userID, exists := middleware.GetUserID(c)

// Get user roles
roles, exists := middleware.GetUserRoles(c)

// Get user permissions
permissions, exists := middleware.GetUserPermissions(c)

// Check if authenticated
if middleware.IsAuthenticated(c) {
    // User is authenticated
}

// Check specific role
if middleware.HasRole(c, "admin") {
    // User has admin role
}

// Check specific permission
if middleware.HasPermission(c, "write") {
    // User has write permission
}

// Check any of multiple roles
if middleware.HasAnyRole(c, "admin", "manager") {
    // User has admin OR manager role
}

// Check all of multiple permissions
if middleware.HasAllPermissions(c, "read", "write") {
    // User has read AND write permissions
}
```

## Configuration

Configure JWT validation in your config file:

```yaml
jwt:
  jwks_url: "https://auth-service/.well-known/jwks.json"
  algorithm: "RS256"
  issuer: "erp-auth-service"
  cache_ttl: "1h"
```

Or using environment variables:

```bash
JWT_JWKS_URL=https://auth-service/.well-known/jwks.json
JWT_ALGORITHM=RS256
JWT_ISSUER=erp-auth-service
JWT_CACHE_TTL=1h
```

## Token Format

The JWT tokens should contain the following claims:

```json
{
  "user_id": "user-123",
  "email": "user@example.com",
  "roles": ["user", "admin"],
  "permissions": ["read", "write", "delete"],
  "exp": 1640995200,
  "iat": 1640991600,
  "iss": "erp-auth-service",
  "sub": "user-123"
}
```

Required claims:
- `user_id` or `sub`: User identifier
- `exp`: Expiration time
- `iss`: Issuer (if configured)

Optional claims:
- `email`: User email
- `roles`: Array of user roles
- `permissions`: Array of user permissions
- `iat`: Issued at time

## Error Responses

All authentication errors return a consistent format:

```json
{
  "success": false,
  "message": "Human-readable error message",
  "errors": {
    "field_name": ["Field-specific error message"]
  }
}
```

Common error responses:

- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Valid token but insufficient permissions
- `500 Internal Server Error`: Server-side validation error

## Performance Considerations

1. **Token Caching**: Validated tokens are cached in Redis to avoid repeated validation
2. **JWKS Caching**: Public keys are cached and refreshed based on TTL
3. **Async Caching**: User claims are cached asynchronously to avoid blocking requests
4. **Connection Pooling**: HTTP client uses connection pooling for JWKS requests

## Security Features

1. **RS256 Signature Verification**: Uses RSA public key cryptography
2. **Key Rotation Support**: Automatically fetches new keys from JWKS endpoint
3. **Token Expiration**: Validates token expiration time
4. **Issuer Validation**: Validates token issuer if configured
5. **Secure Headers**: Extracts tokens only from Authorization header with Bearer scheme

## Testing

The package includes comprehensive tests:

```bash
# Run all tests
go test ./internal/auth -v

# Run specific test
go test ./internal/auth -v -run TestJWTValidator_ValidateToken

# Run integration tests
go test ./internal/auth -v -run TestJWTIntegration
```

## Dependencies

- `github.com/golang-jwt/jwt/v5`: JWT parsing and validation
- `github.com/lestrrat-go/jwx/v2`: JWKS support
- `github.com/gin-gonic/gin`: HTTP middleware
- `github.com/go-redis/redis/v8`: Redis caching (optional)