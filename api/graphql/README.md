# GraphQL API Implementation

This directory contains the GraphQL server implementation for the ERP API Gateway. The GraphQL server provides a unified interface for querying and mutating data across multiple backend services.

## Features

- **gqlgen-based GraphQL server** - Uses the popular gqlgen library for type-safe GraphQL implementation
- **Authentication & Authorization** - Integrates with JWT validation and RBAC middleware
- **DataLoader pattern** - Prevents N+1 query problems with efficient batching
- **Real-time subscriptions** - WebSocket-based subscriptions for live updates
- **GraphQL Playground** - Interactive query interface for development
- **gRPC integration** - Translates GraphQL operations to gRPC calls

## Directory Structure

```
api/graphql/
├── dataloader/          # DataLoader implementation for N+1 prevention
│   └── dataloader.go
├── generated/           # Generated GraphQL server code (auto-generated)
│   └── generated.go
├── helpers/             # Shared helper functions
│   └── conversion.go
├── model/               # GraphQL models (auto-generated and custom)
│   ├── models_gen.go
│   └── models.go
├── resolver/            # GraphQL resolvers
│   ├── helpers.go
│   ├── mutation.resolvers.go
│   ├── query.resolvers.go
│   ├── resolver.go
│   └── subscription.resolvers.go
├── schema/              # GraphQL schema definitions
│   ├── mutation.graphqls
│   ├── query.graphqls
│   ├── subscription.graphqls
│   └── user.graphqls
├── handler.go           # Main GraphQL handler
├── handler_test.go      # Handler tests
├── router.go            # Route setup
└── README.md           # This file
```

## Schema Overview

### Queries

- `me` - Get current authenticated user
- `user(id: ID!)` - Get user by ID (admin only)
- `users(limit: Int, offset: Int, search: String)` - List users (admin only)
- `roles` - Get all roles (admin only)
- `permissions` - Get all permissions (admin only)
- `health` - Health check endpoint

### Mutations

- `login(input: LoginInput!)` - User authentication
- `register(input: RegisterInput!)` - User registration
- `logout` - User logout
- `refreshToken(refreshToken: String!)` - Refresh access token

### Subscriptions

- `userNotifications` - Subscribe to user-specific notifications
- `systemAnnouncements` - Subscribe to system-wide announcements (admin only)

## Usage Examples

### Basic Query

```graphql
{
  me {
    id
    firstName
    lastName
    email
    roles {
      name
    }
    permissions {
      name
    }
  }
}
```

### Login Mutation

```graphql
mutation {
  login(input: {
    email: "user@example.com"
    password: "password123"
  }) {
    user {
      id
      firstName
      lastName
      email
    }
    accessToken
    refreshToken
    expiresIn
  }
}
```

### User Registration

```graphql
mutation {
  register(input: {
    firstName: "John"
    lastName: "Doe"
    email: "john@example.com"
    password: "securepassword"
  }) {
    user {
      id
      email
    }
    accessToken
    expiresIn
  }
}
```

### Real-time Subscription

```graphql
subscription {
  userNotifications {
    id
    type
    title
    message
    read
    createdAt
  }
}
```

## Authentication

The GraphQL server integrates with the gateway's authentication system:

1. **JWT Validation** - Tokens are validated using the auth middleware
2. **User Context** - Authenticated user information is available in resolvers
3. **Permission Checks** - RBAC policies are enforced at the resolver level

### Adding Authentication to Requests

Include the JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## DataLoader Implementation

The DataLoader pattern is implemented to prevent N+1 query problems:

- **User Loader** - Batches user queries by ID
- **Role Loader** - Batches role queries for users
- **Permission Loader** - Batches permission queries for users

### How DataLoader Works

1. Multiple resolvers request the same data
2. DataLoader batches these requests
3. A single gRPC call is made for the batch
4. Results are distributed to all requesting resolvers

## Error Handling

GraphQL errors are handled consistently:

- **Authentication Errors** - Return appropriate error messages
- **Authorization Errors** - Include permission details
- **Service Errors** - Translate gRPC errors to GraphQL errors
- **Validation Errors** - Field-level validation messages

## Testing

Run the GraphQL tests:

```bash
go test ./api/graphql/... -v
```

### Test Coverage

- Handler initialization
- Health query functionality
- GraphQL Playground serving
- Authentication integration (planned)
- Resolver functionality (planned)

## Development

### Regenerating GraphQL Code

When schema files are modified, regenerate the GraphQL code:

```bash
gqlgen generate
```

### Adding New Queries/Mutations

1. Update the appropriate schema file in `schema/`
2. Run `gqlgen generate`
3. Implement the resolver in the appropriate resolver file
4. Add tests for the new functionality

### Adding New Types

1. Define the type in the appropriate schema file
2. Add any custom model methods in `model/models.go`
3. Update conversion helpers if needed

## Integration

### With REST API

The GraphQL server runs alongside the REST API:

- REST endpoints: `/auth/*`, `/api/*`
- GraphQL endpoint: `/graphql`
- GraphQL Playground: `/playground`

### With gRPC Services

GraphQL resolvers translate queries to gRPC calls:

- Auth Service (port 50051)
- CRM Service (port 50052)
- HRM Service (port 50053)
- Finance Service (port 50054)

### With Redis

Redis is used for:

- Caching user data and permissions
- Real-time subscriptions via Pub/Sub
- Session management

### With Kafka

Kafka is used for:

- Publishing business events (login, registration, etc.)
- Event-driven architecture integration

## Performance Considerations

- **DataLoader** - Prevents N+1 queries
- **Query Complexity** - Limited to prevent abuse
- **Caching** - Redis caching for frequently accessed data
- **Connection Pooling** - Efficient gRPC connection management

## Security

- **Input Validation** - All inputs are validated
- **Query Depth Limiting** - Prevents deeply nested queries
- **Rate Limiting** - Applied at the HTTP level
- **CORS** - Configured for allowed origins
- **Authentication** - Required for protected operations

## Monitoring

GraphQL operations are monitored through:

- Request/response logging
- Performance metrics
- Error tracking
- Query complexity analysis

## Future Enhancements

- [ ] Query caching
- [ ] Persisted queries
- [ ] Federation support
- [ ] Advanced subscription filters
- [ ] Query whitelisting
- [ ] Custom scalars
- [ ] File upload support