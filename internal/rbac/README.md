# RBAC (Role-Based Access Control) Implementation

This package provides a comprehensive RBAC implementation for the Go API Gateway, including policy engines, role hierarchies, and middleware for enforcing permissions and roles.

## Components

### 1. Policy Engine (`policy_engine.go`)

The policy engine is responsible for evaluating permissions and roles based on user claims.

#### Features:
- Permission checking with wildcard support (`users:*` matches `users:read`, `users:write`, etc.)
- Role checking with hierarchical inheritance
- Caching for performance optimization
- Super admin role support
- Multiple permission/role checking (any/all)

#### Usage:
```go
// Create policy engine
cache := redis.NewRedisCache(...)
hierarchy := rbac.NewDefaultRoleHierarchy()
config := &interfaces.RBACConfig{
    EnableHierarchy: true,
    CacheTTL:       300,
    SuperAdminRole: "super_admin",
}
policyEngine := rbac.NewDefaultPolicyEngine(cache, hierarchy, config)

// Check permission
hasPermission, err := policyEngine.CheckPermission(ctx, userID, "users:read", claims)

// Check role
hasRole, err := policyEngine.CheckRole(ctx, userID, "admin", claims)
```

### 2. Role Hierarchy (`role_hierarchy.go`)

The role hierarchy manages role relationships and permission inheritance.

#### Default Hierarchy:
```
super_admin (Level 0)
    └── admin (Level 1)
        └── manager (Level 2)
            └── user (Level 3)

guest (Level 4) - standalone role
```

#### Features:
- Hierarchical role inheritance
- Permission aggregation from parent roles
- Cycle detection for hierarchy validation
- Dynamic role addition

#### Usage:
```go
// Create hierarchy
hierarchy := rbac.NewDefaultRoleHierarchy()

// Add custom role
customRole := &interfaces.Role{
    Name:        "developer",
    Description: "Developer role",
    Level:       2,
    ParentRoles: []string{"admin"},
    Permissions: []interfaces.Permission{
        {Name: "code:write", Resource: "code", Action: "write"},
    },
}
hierarchy.AddRole(customRole)

// Get inherited permissions
permissions := hierarchy.GetInheritedPermissions([]string{"user"})
```

### 3. RBAC Middleware (`../middleware/rbac.go`)

The middleware provides Gin handlers for enforcing RBAC policies.

#### Available Middleware:
- `RequirePermission(permission)` - Requires specific permission
- `RequireRole(role)` - Requires specific role
- `RequireAnyPermission(permissions...)` - Requires any of the permissions
- `RequireAllPermissions(permissions...)` - Requires all permissions
- `RequireAnyRole(roles...)` - Requires any of the roles
- `RequireAllRoles(roles...)` - Requires all roles
- `RequireResourcePermission(resource, action)` - Requires resource-action permission
- `RequireSuperAdmin()` - Requires super admin role
- `AllowGuest()` - Allows guest access (no auth required)

#### Usage:
```go
// Setup RBAC middleware
policyEngine := rbac.NewDefaultPolicyEngine(cache, hierarchy, config)
rbacMiddleware := middleware.NewRBACMiddleware(policyEngine, config)

// Use in routes
router.GET("/users", 
    authMiddleware.RequireAuth(),
    rbacMiddleware.RequirePermission("users:read"),
    userHandler.GetUsers)

router.POST("/admin/users", 
    authMiddleware.RequireAuth(),
    rbacMiddleware.RequireRole("admin"),
    adminHandler.CreateUser)

router.GET("/reports", 
    authMiddleware.RequireAuth(),
    rbacMiddleware.RequireAnyPermission("reports:read", "admin:read"),
    reportHandler.GetReports)
```

## Configuration

### RBAC Config Structure:
```go
type RBACConfig struct {
    EnableHierarchy     bool   `json:"enable_hierarchy"`      // Enable role hierarchy
    CacheTTL           int    `json:"cache_ttl_seconds"`      // Cache TTL in seconds
    DefaultDenyAll     bool   `json:"default_deny_all"`       // Default deny policy
    SuperAdminRole     string `json:"super_admin_role"`       // Super admin role name
    GuestRole          string `json:"guest_role"`             // Guest role name
    PermissionFormat   string `json:"permission_format"`      // Permission format (resource:action)
}
```

### Environment Variables:
```bash
RBAC_ENABLE_HIERARCHY=true
RBAC_CACHE_TTL=300
RBAC_SUPER_ADMIN_ROLE=super_admin
RBAC_GUEST_ROLE=guest
RBAC_PERMISSION_FORMAT=resource:action
```

## Permission Formats

The system supports multiple permission formats:

1. **resource:action** (default) - `users:read`, `projects:write`
2. **resource.action** - `users.read`, `projects.write`
3. **action_resource** - `read_users`, `write_projects`

## Default Roles and Permissions

### Super Admin
- **Permissions**: `*:*` (all permissions)
- **Description**: Full system access

### Admin
- **Permissions**: `users:*`, `roles:*`, `system:read`
- **Inherits**: super_admin permissions
- **Description**: Administrative access

### Manager
- **Permissions**: `team:*`, `projects:*`, `reports:read`
- **Inherits**: admin permissions
- **Description**: Team and project management

### User
- **Permissions**: `profile:read`, `profile:update`, `dashboard:read`
- **Inherits**: manager permissions
- **Description**: Regular user access

### Guest
- **Permissions**: `public:read`
- **Description**: Public access only

## Helper Functions

The middleware provides helper functions for programmatic permission checking:

```go
// Check if user has permission
if middleware.CheckUserPermission(c, policyEngine, "users:read") {
    // User has permission
}

// Check if user has role
if middleware.CheckUserRole(c, policyEngine, "admin") {
    // User has role
}

// Check ownership or permission
if middleware.IsOwnerOrHasPermission(c, policyEngine, resourceOwnerID, "admin:write") {
    // User is owner or has permission
}
```

## Caching

The system implements Redis-based caching for performance:

- **Permission Cache**: Caches user permissions with configurable TTL
- **Role Cache**: Caches role hierarchy lookups
- **JWT Cache**: Caches JWT validation results

Cache keys follow the pattern:
- `rbac:permissions:{userID}` - User permissions
- `rbac:roles:{userID}` - User roles
- `user:claims:{userID}` - User claims

## Testing

Comprehensive unit tests are provided:

```bash
# Run RBAC tests
go test ./internal/rbac -v

# Run middleware tests
go test ./middleware -v

# Run with coverage
go test ./internal/rbac ./middleware -cover
```

## Integration Example

```go
package main

import (
    "go-api-gateway/internal/rbac"
    "go-api-gateway/middleware"
    "go-api-gateway/internal/interfaces"
)

func setupRBAC(cache interfaces.CacheService) (*middleware.RBACMiddleware, error) {
    // Create role hierarchy
    hierarchy := rbac.NewDefaultRoleHierarchy()
    
    // Create RBAC config
    config := &interfaces.RBACConfig{
        EnableHierarchy:   true,
        CacheTTL:         300,
        DefaultDenyAll:   true,
        SuperAdminRole:   "super_admin",
        GuestRole:        "guest",
        PermissionFormat: "resource:action",
    }
    
    // Create policy engine
    policyEngine := rbac.NewDefaultPolicyEngine(cache, hierarchy, config)
    
    // Create RBAC middleware
    rbacMiddleware := middleware.NewRBACMiddleware(policyEngine, config)
    
    return rbacMiddleware, nil
}

func setupRoutes(router *gin.Engine, authMiddleware *middleware.AuthMiddleware, rbacMiddleware *middleware.RBACMiddleware) {
    // Public routes
    router.GET("/health", rbacMiddleware.AllowGuest(), healthHandler)
    
    // User routes
    userGroup := router.Group("/users")
    userGroup.Use(authMiddleware.RequireAuth())
    {
        userGroup.GET("", rbacMiddleware.RequirePermission("users:read"), getUsersHandler)
        userGroup.POST("", rbacMiddleware.RequirePermission("users:write"), createUserHandler)
        userGroup.PUT("/:id", rbacMiddleware.RequireAnyPermission("users:write", "admin:write"), updateUserHandler)
        userGroup.DELETE("/:id", rbacMiddleware.RequireRole("admin"), deleteUserHandler)
    }
    
    // Admin routes
    adminGroup := router.Group("/admin")
    adminGroup.Use(authMiddleware.RequireAuth())
    adminGroup.Use(rbacMiddleware.RequireRole("admin"))
    {
        adminGroup.GET("/users", adminGetUsersHandler)
        adminGroup.POST("/roles", adminCreateRoleHandler)
    }
    
    // Super admin routes
    superAdminGroup := router.Group("/superadmin")
    superAdminGroup.Use(authMiddleware.RequireAuth())
    superAdminGroup.Use(rbacMiddleware.RequireSuperAdmin())
    {
        superAdminGroup.GET("/system", systemStatusHandler)
    }
}
```

## Security Considerations

1. **Default Deny**: The system defaults to denying access unless explicitly granted
2. **Principle of Least Privilege**: Users should only have the minimum permissions needed
3. **Role Hierarchy**: Higher-level roles inherit permissions from lower-level roles
4. **Cache Security**: Cached permissions are invalidated when roles/permissions change
5. **Audit Logging**: All permission checks should be logged for security auditing

## Performance Optimization

1. **Caching**: Permissions and roles are cached in Redis
2. **Wildcard Permissions**: Use wildcards (`users:*`) to reduce permission checks
3. **Hierarchy Optimization**: Role hierarchy is pre-computed and cached
4. **Async Operations**: Cache operations are performed asynchronously when possible

## Troubleshooting

### Common Issues:

1. **Permission Denied**: Check if user has required role/permission
2. **Cache Issues**: Verify Redis connection and cache TTL settings
3. **Hierarchy Cycles**: Validate role hierarchy for circular dependencies
4. **Token Expiry**: Ensure JWT tokens are valid and not expired

### Debug Commands:
```bash
# Check user permissions
curl -H "Authorization: Bearer $TOKEN" /debug/permissions

# Validate role hierarchy
curl -H "Authorization: Bearer $ADMIN_TOKEN" /debug/roles/validate

# Clear permission cache
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" /debug/cache/permissions/{userID}
```