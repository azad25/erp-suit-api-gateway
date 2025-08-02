# ERP API Gateway - API Documentation

## OpenAPI 3.0 Specification

```yaml
openapi: 3.0.3
info:
  title: ERP API Gateway
  description: |
    Enterprise Resource Planning API Gateway providing REST, GraphQL, and WebSocket endpoints.
    This gateway serves as the central entry point for the ERP system, handling authentication,
    authorization, and routing to backend microservices.
  version: 1.0.0
  contact:
    name: ERP Development Team
    email: dev@erp-system.com
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT

servers:
  - url: https://api.erp-system.com
    description: Production server
  - url: https://staging-api.erp-system.com
    description: Staging server
  - url: http://localhost:8080
    description: Development server

security:
  - BearerAuth: []

paths:
  # Authentication Endpoints
  /auth/login/:
    post:
      tags:
        - Authentication
      summary: User Login
      description: Authenticate user with email and password
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
            examples:
              valid_login:
                summary: Valid login credentials
                value:
                  email: "user@example.com"
                  password: "securepassword123"
                  remember_me: true
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'
              examples:
                success:
                  summary: Successful login
                  value:
                    success: true
                    data:
                      user:
                        id: "123e4567-e89b-12d3-a456-426614174000"
                        first_name: "John"
                        last_name: "Doe"
                        email: "user@example.com"
                        email_verified_at: "2024-01-15T10:30:00Z"
                        created_at: "2024-01-01T00:00:00Z"
                        updated_at: "2024-01-15T10:30:00Z"
                      access_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
                      refresh_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
                      expires_in: 3600
                    message: "Login successful"
        '400':
          description: Invalid request data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
              examples:
                validation_error:
                  summary: Validation errors
                  value:
                    success: false
                    message: "Validation failed"
                    errors:
                      email: ["Email is required"]
                      password: ["Password must be at least 8 characters"]
        '401':
          description: Invalid credentials
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
              examples:
                invalid_credentials:
                  summary: Invalid credentials
                  value:
                    success: false
                    message: "Invalid email or password"
                    errors: {}
        '429':
          description: Too many requests
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Internal server error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /auth/register/:
    post:
      tags:
        - Authentication
      summary: User Registration
      description: Register a new user account
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterRequest'
            examples:
              valid_registration:
                summary: Valid registration data
                value:
                  first_name: "John"
                  last_name: "Doe"
                  email: "newuser@example.com"
                  password: "securepassword123"
                  password_confirmation: "securepassword123"
      responses:
        '201':
          description: Registration successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegisterResponse'
        '400':
          description: Invalid request data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '409':
          description: Email already exists
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Internal server error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /auth/refresh/:
    post:
      tags:
        - Authentication
      summary: Refresh Access Token
      description: Get a new access token using refresh token
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RefreshTokenRequest'
      responses:
        '200':
          description: Token refresh successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RefreshTokenResponse'
        '400':
          description: Invalid refresh token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '401':
          description: Refresh token expired
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /auth/logout/:
    post:
      tags:
        - Authentication
      summary: User Logout
      description: Logout user and invalidate tokens
      responses:
        '200':
          description: Logout successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LogoutResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /auth/me/:
    get:
      tags:
        - Authentication
      summary: Get Current User
      description: Get current authenticated user information
      responses:
        '200':
          description: User information retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  # Health Check Endpoints
  /health:
    get:
      tags:
        - Health
      summary: Health Check
      description: Basic health check endpoint
      security: []
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'
              examples:
                healthy:
                  summary: Healthy service
                  value:
                    status: "healthy"
                    timestamp: "2024-01-15T10:30:00Z"
                    uptime: "2h30m15s"

  /ready:
    get:
      tags:
        - Health
      summary: Readiness Check
      description: Readiness check with dependency validation
      security: []
      responses:
        '200':
          description: Service is ready
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReadinessResponse'
              examples:
                ready:
                  summary: Service ready
                  value:
                    status: "ready"
                    timestamp: "2024-01-15T10:30:00Z"
                    dependencies:
                      redis: "healthy"
                      kafka: "healthy"
                      auth_service: "healthy"
                      crm_service: "healthy"
        '503':
          description: Service not ready
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReadinessResponse'

  /metrics:
    get:
      tags:
        - Monitoring
      summary: Prometheus Metrics
      description: Prometheus-compatible metrics endpoint
      security: []
      responses:
        '200':
          description: Metrics data
          content:
            text/plain:
              schema:
                type: string
                example: |
                  # HELP http_requests_total Total number of HTTP requests
                  # TYPE http_requests_total counter
                  http_requests_total{method="GET",status="200"} 1234
                  
                  # HELP http_request_duration_seconds HTTP request duration
                  # TYPE http_request_duration_seconds histogram
                  http_request_duration_seconds_bucket{le="0.1"} 100

  # GraphQL Endpoint
  /graphql:
    post:
      tags:
        - GraphQL
      summary: GraphQL Endpoint
      description: Execute GraphQL queries and mutations
      security:
        - BearerAuth: []
        - {}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/GraphQLRequest'
            examples:
              user_query:
                summary: Get user information
                value:
                  query: |
                    query GetUser($id: ID!) {
                      user(id: $id) {
                        id
                        firstName
                        lastName
                        email
                      }
                    }
                  variables:
                    id: "123e4567-e89b-12d3-a456-426614174000"
      responses:
        '200':
          description: GraphQL response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/GraphQLResponse'
        '400':
          description: GraphQL query error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/GraphQLErrorResponse'

    get:
      tags:
        - GraphQL
      summary: GraphQL Playground
      description: GraphQL Playground interface (development only)
      security: []
      responses:
        '200':
          description: GraphQL Playground HTML
          content:
            text/html:
              schema:
                type: string

  # WebSocket Endpoint
  /ws:
    get:
      tags:
        - WebSocket
      summary: WebSocket Connection
      description: Upgrade HTTP connection to WebSocket for real-time communication
      parameters:
        - name: Authorization
          in: header
          required: true
          schema:
            type: string
            example: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        - name: Upgrade
          in: header
          required: true
          schema:
            type: string
            enum: [websocket]
        - name: Connection
          in: header
          required: true
          schema:
            type: string
            enum: [Upgrade]
      responses:
        '101':
          description: WebSocket connection established
        '400':
          description: Bad request - invalid WebSocket upgrade
        '401':
          description: Unauthorized - invalid or missing token
        '426':
          description: Upgrade required

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: |
        JWT token obtained from login endpoint.
        Format: `Bearer <token>`

  schemas:
    # Request Schemas
    LoginRequest:
      type: object
      required:
        - email
        - password
      properties:
        email:
          type: string
          format: email
          description: User email address
          example: "user@example.com"
        password:
          type: string
          minLength: 8
          description: User password
          example: "securepassword123"
        remember_me:
          type: boolean
          description: Whether to issue long-lived refresh token
          default: false
          example: true

    RegisterRequest:
      type: object
      required:
        - first_name
        - last_name
        - email
        - password
        - password_confirmation
      properties:
        first_name:
          type: string
          minLength: 1
          maxLength: 50
          description: User first name
          example: "John"
        last_name:
          type: string
          minLength: 1
          maxLength: 50
          description: User last name
          example: "Doe"
        email:
          type: string
          format: email
          description: User email address
          example: "newuser@example.com"
        password:
          type: string
          minLength: 8
          description: User password
          example: "securepassword123"
        password_confirmation:
          type: string
          minLength: 8
          description: Password confirmation
          example: "securepassword123"

    RefreshTokenRequest:
      type: object
      required:
        - refresh_token
      properties:
        refresh_token:
          type: string
          description: Refresh token from login response
          example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

    GraphQLRequest:
      type: object
      required:
        - query
      properties:
        query:
          type: string
          description: GraphQL query string
          example: "query { user(id: \"123\") { id firstName lastName } }"
        variables:
          type: object
          description: GraphQL query variables
          additionalProperties: true
          example:
            id: "123e4567-e89b-12d3-a456-426614174000"
        operationName:
          type: string
          description: GraphQL operation name
          example: "GetUser"

    # Response Schemas
    LoginResponse:
      type: object
      properties:
        success:
          type: boolean
          description: Whether the operation was successful
          example: true
        data:
          $ref: '#/components/schemas/AuthData'
        message:
          type: string
          description: Success message
          example: "Login successful"
        errors:
          type: object
          additionalProperties:
            type: array
            items:
              type: string
          description: Validation errors (if any)
          example: {}

    RegisterResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          $ref: '#/components/schemas/AuthData'
        message:
          type: string
          example: "Registration successful"
        errors:
          type: object
          additionalProperties:
            type: array
            items:
              type: string
          example: {}

    RefreshTokenResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          $ref: '#/components/schemas/TokenPair'
        message:
          type: string
          example: "Token refreshed successfully"
        errors:
          type: object
          additionalProperties:
            type: array
            items:
              type: string
          example: {}

    LogoutResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        message:
          type: string
          example: "Logout successful"

    UserResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          $ref: '#/components/schemas/User'
        message:
          type: string
          example: "User information retrieved"

    HealthResponse:
      type: object
      properties:
        status:
          type: string
          enum: [healthy, unhealthy]
          example: "healthy"
        timestamp:
          type: string
          format: date-time
          example: "2024-01-15T10:30:00Z"
        uptime:
          type: string
          description: Service uptime
          example: "2h30m15s"

    ReadinessResponse:
      type: object
      properties:
        status:
          type: string
          enum: [ready, not_ready]
          example: "ready"
        timestamp:
          type: string
          format: date-time
          example: "2024-01-15T10:30:00Z"
        dependencies:
          type: object
          additionalProperties:
            type: string
            enum: [healthy, unhealthy]
          example:
            redis: "healthy"
            kafka: "healthy"
            auth_service: "healthy"
            crm_service: "healthy"

    GraphQLResponse:
      type: object
      properties:
        data:
          type: object
          description: GraphQL query result
          additionalProperties: true
        errors:
          type: array
          items:
            $ref: '#/components/schemas/GraphQLError'
          description: GraphQL errors (if any)
        extensions:
          type: object
          description: GraphQL extensions
          additionalProperties: true

    GraphQLErrorResponse:
      type: object
      properties:
        errors:
          type: array
          items:
            $ref: '#/components/schemas/GraphQLError'

    ErrorResponse:
      type: object
      properties:
        success:
          type: boolean
          example: false
        message:
          type: string
          description: Error message
          example: "An error occurred"
        errors:
          type: object
          additionalProperties:
            type: array
            items:
              type: string
          description: Field-specific errors
          example:
            email: ["Email is required"]
            password: ["Password must be at least 8 characters"]

    # Data Models
    AuthData:
      type: object
      properties:
        user:
          $ref: '#/components/schemas/User'
        access_token:
          type: string
          description: JWT access token
          example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        refresh_token:
          type: string
          description: JWT refresh token
          example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        expires_in:
          type: integer
          description: Token expiration time in seconds
          example: 3600

    TokenPair:
      type: object
      properties:
        access_token:
          type: string
          description: JWT access token
          example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        refresh_token:
          type: string
          description: JWT refresh token
          example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        expires_in:
          type: integer
          description: Token expiration time in seconds
          example: 3600

    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
          description: User unique identifier
          example: "123e4567-e89b-12d3-a456-426614174000"
        first_name:
          type: string
          description: User first name
          example: "John"
        last_name:
          type: string
          description: User last name
          example: "Doe"
        email:
          type: string
          format: email
          description: User email address
          example: "user@example.com"
        email_verified_at:
          type: string
          format: date-time
          nullable: true
          description: Email verification timestamp
          example: "2024-01-15T10:30:00Z"
        created_at:
          type: string
          format: date-time
          description: Account creation timestamp
          example: "2024-01-01T00:00:00Z"
        updated_at:
          type: string
          format: date-time
          description: Last update timestamp
          example: "2024-01-15T10:30:00Z"

    GraphQLError:
      type: object
      properties:
        message:
          type: string
          description: Error message
          example: "Field 'user' not found"
        locations:
          type: array
          items:
            type: object
            properties:
              line:
                type: integer
              column:
                type: integer
          description: Error locations in query
        path:
          type: array
          items:
            oneOf:
              - type: string
              - type: integer
          description: Path to the field that caused the error
        extensions:
          type: object
          description: Additional error information
          additionalProperties: true

tags:
  - name: Authentication
    description: User authentication and authorization endpoints
  - name: Health
    description: Service health and readiness checks
  - name: Monitoring
    description: Metrics and monitoring endpoints
  - name: GraphQL
    description: GraphQL query and mutation endpoint
  - name: WebSocket
    description: Real-time WebSocket communication

externalDocs:
  description: Find more information about the ERP API Gateway
  url: https://docs.erp-system.com/api-gateway
```

## API Usage Examples

### Authentication Flow

#### 1. User Login
```bash
curl -X POST https://api.erp-system.com/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "remember_me": true
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "first_name": "John",
      "last_name": "Doe",
      "email": "user@example.com",
      "email_verified_at": "2024-01-15T10:30:00Z",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    },
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600
  },
  "message": "Login successful"
}
```

#### 2. Access Protected Endpoint
```bash
curl -X GET https://api.erp-system.com/auth/me/ \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### 3. Refresh Token
```bash
curl -X POST https://api.erp-system.com/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

### GraphQL Usage

#### Query Example
```bash
curl -X POST https://api.erp-system.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "query": "query GetUser($id: ID!) { user(id: $id) { id firstName lastName email } }",
    "variables": { "id": "123e4567-e89b-12d3-a456-426614174000" }
  }'
```

#### Mutation Example
```bash
curl -X POST https://api.erp-system.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "query": "mutation UpdateUser($id: ID!, $input: UpdateUserInput!) { updateUser(id: $id, input: $input) { id firstName lastName } }",
    "variables": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "input": { "firstName": "Jane", "lastName": "Smith" }
    }
  }'
```

### WebSocket Usage

#### JavaScript Example
```javascript
// Establish WebSocket connection
const ws = new WebSocket('wss://api.erp-system.com/ws', [], {
  headers: {
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
  }
});

ws.onopen = function(event) {
  console.log('WebSocket connected');
  
  // Subscribe to user notifications
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'notifications:user-123'
  }));
};

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Received message:', message);
};

ws.onclose = function(event) {
  console.log('WebSocket disconnected');
};

ws.onerror = function(error) {
  console.error('WebSocket error:', error);
};
```

#### Node.js Example
```javascript
const WebSocket = require('ws');

const ws = new WebSocket('wss://api.erp-system.com/ws', {
  headers: {
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
  }
});

ws.on('open', function open() {
  console.log('Connected to WebSocket');
  
  // Send subscription message
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'notifications:user-123'
  }));
});

ws.on('message', function message(data) {
  const msg = JSON.parse(data);
  console.log('Received:', msg);
});
```

## Error Handling

### HTTP Status Codes

| Status Code | Description | Usage |
|-------------|-------------|-------|
| 200 | OK | Successful request |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Unprocessable Entity | Validation errors |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 502 | Bad Gateway | Backend service error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Error Response Format

All error responses follow a consistent format:

```json
{
  "success": false,
  "message": "Human-readable error description",
  "errors": {
    "field_name": ["Field-specific error message"],
    "another_field": ["Another error message"]
  }
}
```

### Common Error Examples

#### Validation Error (400)
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": {
    "email": ["Email is required", "Email format is invalid"],
    "password": ["Password must be at least 8 characters"]
  }
}
```

#### Authentication Error (401)
```json
{
  "success": false,
  "message": "Authentication failed",
  "errors": {
    "token": ["Token is expired or invalid"]
  }
}
```

#### Authorization Error (403)
```json
{
  "success": false,
  "message": "Insufficient permissions",
  "errors": {
    "permission": ["User does not have required permission: read:users"]
  }
}
```

#### Rate Limit Error (429)
```json
{
  "success": false,
  "message": "Rate limit exceeded",
  "errors": {
    "rate_limit": ["Too many requests. Try again in 60 seconds"]
  }
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

### Rate Limit Headers

All responses include rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
X-RateLimit-Window: 60
```

### Rate Limit Policies

| Endpoint Category | Limit | Window | Scope |
|------------------|-------|--------|-------|
| Authentication | 10 requests | 1 minute | Per IP |
| General API | 100 requests | 1 minute | Per user |
| GraphQL | 50 requests | 1 minute | Per user |
| WebSocket | 5 connections | - | Per user |

## Pagination

For endpoints that return lists, pagination is implemented using cursor-based pagination:

### Request Parameters
- `limit`: Number of items per page (default: 20, max: 100)
- `cursor`: Cursor for next page (optional)

### Response Format
```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "has_next": true,
    "has_previous": false,
    "next_cursor": "eyJpZCI6IjEyMyIsInRpbWVzdGFtcCI6MTY0MDk5NTIwMH0=",
    "previous_cursor": null,
    "total_count": 150
  }
}
```

## Versioning

The API uses URL versioning:

- Current version: `v1`
- Base URL: `https://api.erp-system.com/api/v1/`
- Backward compatibility maintained for at least 2 major versions

### Version Headers

Clients can specify API version using headers:

```
Accept: application/vnd.erp-api.v1+json
API-Version: v1
```

## CORS Policy

Cross-Origin Resource Sharing (CORS) is configured to allow requests from approved origins:

### Allowed Origins
- `https://app.erp-system.com` (Production frontend)
- `https://staging-app.erp-system.com` (Staging frontend)
- `http://localhost:3000` (Development frontend)

### Allowed Methods
- GET, POST, PUT, DELETE, OPTIONS

### Allowed Headers
- Authorization, Content-Type, Accept, X-Requested-With

### Preflight Requests
The API supports CORS preflight requests for complex requests.

## Security Considerations

### Authentication
- JWT tokens with RS256 signature
- Token expiration: 1 hour (access), 30 days (refresh)
- JWKS endpoint for key rotation

### Authorization
- Role-based access control (RBAC)
- Permission-based authorization
- Resource-level access control

### Transport Security
- HTTPS/TLS 1.3 required for all endpoints
- HSTS headers enforced
- Certificate pinning recommended

### Input Validation
- All inputs validated and sanitized
- SQL injection prevention
- XSS protection
- CSRF protection for state-changing operations

---

This API documentation provides comprehensive information about the ERP API Gateway endpoints, request/response formats, authentication, error handling, and security considerations. For implementation details and advanced usage, refer to the technical documentation and SDK documentation.