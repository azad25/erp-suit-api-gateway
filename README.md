# ERP Core API Gateway

A Django-based API Gateway that serves as the central entry point for the ERP Suite, integrating with the Auth Service for authentication and authorization.

## 🚀 Features

- **Central API Gateway** - Single entry point for all ERP services
- **Auth Service Integration** - Seamless authentication with the auth-module
- **Multi-tenant Support** - Tenant isolation and management
- **API Documentation** - Auto-generated OpenAPI/Swagger documentation
- **Health Monitoring** - Comprehensive health checks and metrics
- **Rate Limiting** - Built-in request throttling
- **CORS Support** - Cross-origin resource sharing
- **Redis Caching** - High-performance caching layer

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Mobile App    │    │   API Clients   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │   ERP Core API Gateway    │
                    │      (Django)             │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │     Auth Service          │
                    │      (Go)                 │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   Infrastructure          │
                    │   (PostgreSQL, Redis)     │
                    └───────────────────────────┘
```

## 🛠️ Technology Stack

- **Framework**: Django 4.2+ with Django REST Framework
- **Authentication**: JWT with Auth Service integration
- **Database**: PostgreSQL 15+
- **Cache**: Redis 7+
- **Documentation**: drf-spectacular (OpenAPI/Swagger)
- **Monitoring**: Health checks and metrics
- **Containerization**: Docker & Docker Compose

## 📋 Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose
- Auth Service running (auth-module)

## 🚀 Quick Start

### Using Docker (Recommended)

1. **Clone and navigate to the project**:
   ```bash
   cd erp-suite/erp-django-core-app
   ```

2. **Start the services**:
   ```bash
   make docker-run
   ```

3. **Check the service**:
   ```bash
   make health
   ```

4. **View logs**:
   ```bash
   make logs
   ```

### Local Development

1. **Install dependencies**:
   ```bash
   make install
   ```

2. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run migrations**:
   ```bash
   make migrate
   ```

4. **Start development server**:
   ```bash
   make dev
   ```

## 📊 API Endpoints

### Core Gateway
- `GET /api/v1/gateway/` - Gateway information
- `GET /api/v1/health/` - Health check
- `GET /api/v1/status/` - Service status
- `GET /api/v1/info/` - API information

### Authentication (Proxied to Auth Service)
- `POST /api/v1/auth/login/` - User login
- `POST /api/v1/auth/logout/` - User logout
- `POST /api/v1/auth/register/` - User registration
- `POST /api/v1/auth/refresh/` - Token refresh
- `GET /api/v1/auth/validate/` - Token validation

### User Management (Proxied to Auth Service)
- `GET /api/v1/auth/users/` - List users
- `GET /api/v1/auth/users/{id}/` - User details
- `GET /api/v1/auth/users/{id}/permissions/` - User permissions

### Monitoring
- `GET /api/v1/monitoring/metrics/` - System metrics
- `GET /api/v1/monitoring/performance/` - Performance metrics
- `GET /api/v1/monitoring/health/detailed/` - Detailed health check

### Documentation
- `GET /api/docs/` - Swagger UI
- `GET /api/redoc/` - ReDoc documentation
- `GET /api/schema/` - OpenAPI schema

## 🔧 Configuration

### Environment Variables

```bash
# Django
DEBUG=True
SECRET_KEY=your-secret-key
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=erp_core
DB_USER=postgres
DB_PASSWORD=postgres

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=redispassword

# Auth Service
AUTH_SERVICE_URL=http://localhost:8080
AUTH_SERVICE_GRPC_HOST=localhost
AUTH_SERVICE_GRPC_PORT=50051
AUTH_SERVICE_TIMEOUT=5
AUTH_SERVICE_RETRY_ATTEMPTS=3
```

### Auth Service Integration

The API Gateway integrates with the Auth Service for:

- **Token Validation** - Validates JWT tokens with the auth service
- **User Authentication** - Proxies login/logout requests
- **Permission Checking** - Validates user permissions
- **User Management** - Proxies user CRUD operations

## 🔐 Authentication

### JWT Token Flow

1. **Login**: Client sends credentials to `/api/v1/auth/login/`
2. **Token Validation**: Gateway validates tokens with Auth Service
3. **Request Processing**: Gateway processes authenticated requests
4. **Token Refresh**: Client can refresh tokens via `/api/v1/auth/refresh/`

### Example Usage

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password"}'

# Use token
curl -X GET http://localhost:8000/api/v1/gateway/ \
  -H "Authorization: Bearer <your-token>"
```

## 📈 Monitoring

### Health Checks

- **Basic Health**: `GET /api/v1/health/`
- **Service Status**: `GET /api/v1/status/`
- **Detailed Health**: `GET /api/v1/monitoring/health/detailed/`

### Metrics

- **System Metrics**: CPU, memory, disk usage
- **Performance Metrics**: Database, cache, auth service response times
- **Error Metrics**: Error rates and status codes

## 🧪 Testing

```bash
# Run tests
make test

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test
pytest tests/test_auth_integration.py
```

## 🐳 Docker

### Build and Run

```bash
# Build image
make docker-build

# Run containers
make docker-run

# Stop containers
make docker-stop

# View logs
make logs
```

### Docker Compose Services

- **erp-django-core**: Django API Gateway (port 8000)
- **postgres**: PostgreSQL database (port 5432)
- **redis**: Redis cache (port 6379)
- **auth-service**: Auth Service (ports 8080, 50051)

## 🔧 Development

### Available Commands

```bash
make help              # Show all commands
make install           # Install dependencies
make dev               # Run development server
make test              # Run tests
make migrate           # Run migrations
make shell             # Open Django shell
make lint              # Run linting
make format            # Format code
```

### Code Quality

```bash
# Format code
make format

# Check linting
make lint

# Run security checks
bandit -r .
```

## 📚 Documentation

- **API Documentation**: http://localhost:8000/api/docs/
- **ReDoc**: http://localhost:8000/api/redoc/
- **OpenAPI Schema**: http://localhost:8000/api/schema/

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions:

- Check the API documentation
- Review the health endpoints
- Check the logs: `make logs`
- Open an issue in the repository 