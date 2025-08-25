# AI Copilot Integration - ERP API Gateway

## Overview

This document provides comprehensive technical documentation for the AI Copilot integration into the ERP API Gateway. The integration enables real-time AI-powered assistance through WebSocket connections, REST APIs, and gRPC communication with the AI Copilot service.

## Architecture Overview

The AI Copilot integration follows a microservices architecture pattern with the following components:

- **API Gateway**: Central entry point handling WebSocket connections, REST APIs, and routing
- **AI Copilot Service**: Python-based service providing AI chat capabilities and streaming responses
- **gRPC Communication**: High-performance communication between gateway and AI service
- **WebSocket Layer**: Real-time bidirectional communication for chat and streaming
- **REST API**: HTTP endpoints for AI-related operations

## Modified and Created Files

### Core Interface Files

#### `internal/interfaces/websocket.go`
**Purpose**: Defines WebSocket interfaces and message types for AI integration

**Key Additions**:
- AI message types: `MessageTypeAIChat`, `MessageTypeAIStream`, `MessageTypeAIStatus`
- WebSocket interfaces for connection management
- Message structures for AI communication

```go
// AI Message Types
const (
    MessageTypeAIChat   MessageType = "ai_chat"
    MessageTypeAIStream MessageType = "ai_stream"
    MessageTypeAIStatus MessageType = "ai_status"
)

// AI Request/Response Structures
type AIChatRequest struct {
    Message   string            `json:"message"`
    Context   map[string]string `json:"context,omitempty"`
    SessionID string            `json:"session_id,omitempty"`
}

type AIChatResponse struct {
    Response  string `json:"response"`
    MessageID string `json:"message_id"`
    Timestamp int64  `json:"timestamp"`
}

type AIStreamResponse struct {
    Content   string `json:"content"`
    IsFinal   bool   `json:"is_final"`
    MessageID string `json:"message_id"`
}
```

### WebSocket Handler Files

#### `api/ws/handler.go`
**Purpose**: Main WebSocket handler implementing AI Copilot integration

**Key Features**:
- AI service client initialization
- Message routing for AI chat and streaming
- Connection lifecycle management
- Error handling and validation

**Core Functions**:
- `handleAIChat()`: Handles AI chat requests via WebSocket
- `handleAIStream()`: Manages streaming AI responses
- `validateAIMessage()`: Validates AI-related messages

#### `api/ws/connection.go`
**Purpose**: WebSocket connection management with AI message handling

**Key Features**:
- Connection state management
- AI message processing
- Channel-based communication
- Streaming support implementation

**Core Methods**:
- `handleAIChat()`: Process AI chat messages
- `handleAIStream()`: Handle streaming AI responses
- `sendAIResponse()`: Send AI responses to client

### REST API Files

#### `api/rest/ai_handler.go`
**Purpose**: REST API endpoints for AI Copilot operations

**Endpoints**:
- `POST /api/ai/chat`: Send AI chat request
- `POST /api/ai/stream`: Initiate AI streaming session
- `GET /api/ai/status`: Get AI service status

**Request/Response Models**:
```go
type AIChatRequest struct {
    Message   string            `json:"message"`
    Context   map[string]string `json:"context,omitempty"`
    UserID    string            `json:"user_id"`
    SessionID string            `json:"session_id,omitempty"`
}

type AIChatResponse struct {
    Response  string `json:"response"`
    MessageID string `json:"message_id"`
    Timestamp int64  `json:"timestamp"`
}
```

### Service Integration Files

#### `internal/services/grpc_client/ai_client.go`
**Purpose**: gRPC client for AI Copilot service communication

**Key Features**:
- Connection pooling for AI service
- Retry mechanism with exponential backoff
- Health checking and circuit breaker pattern
- Streaming support for real-time responses

**Core Methods**:
- `SendChatRequest()`: Send chat request to AI service
- `StartStreamSession()`: Initiate streaming session
- `GetServiceHealth()`: Check AI service health

## Communication Flows

### WebSocket AI Chat Flow

1. **Client Connection**
   ```
   Client → WebSocket Upgrade → API Gateway → Connection Established
   ```

2. **AI Chat Request**
   ```
   Client → WebSocket Message (MessageTypeAIChat) → Handler → AI Service (gRPC)
   ```

3. **AI Response**
   ```
   AI Service → gRPC Response → Handler → WebSocket Message → Client
   ```

### Streaming AI Response Flow

1. **Stream Initiation**
   ```
   Client → WebSocket Message (MessageTypeAIStream) → Handler → AI Service (gRPC Stream)
   ```

2. **Streaming Response**
   ```
   AI Service → gRPC Stream → Handler → WebSocket Stream Messages → Client
   ```

### REST API Flow

1. **HTTP Request**
   ```
   Client → HTTP POST /api/ai/chat → REST Handler → AI Service (gRPC)
   ```

2. **HTTP Response**
   ```
   AI Service → gRPC Response → REST Handler → HTTP Response → Client
   ```

## Message Structures

### WebSocket Messages

#### AI Chat Message
```json
{
  "type": "ai_chat",
  "data": {
    "message": "How can I help you today?",
    "context": {
      "user_id": "12345",
      "department": "sales"
    },
    "session_id": "sess_abc123"
  },
  "timestamp": 1640995200000
}
```

#### AI Stream Message
```json
{
  "type": "ai_stream",
  "data": {
    "message": "Generate a sales report for Q1",
    "context": {
      "user_id": "12345",
      "department": "sales"
    }
  },
  "timestamp": 1640995200000
}
```

#### AI Status Message
```json
{
  "type": "ai_status",
  "data": {
    "status": "processing",
    "message_id": "msg_xyz789",
    "progress": 45
  },
  "timestamp": 1640995200000
}
```

### gRPC Protocol Buffers

#### AI Service Protocol
```protobuf
syntax = "proto3";

package ai;

service AICopilot {
  rpc Chat(ChatRequest) returns (ChatResponse);
  rpc StreamChat(StreamRequest) returns (stream StreamResponse);
  rpc HealthCheck(HealthRequest) returns (HealthResponse);
}

message ChatRequest {
  string message = 1;
  map<string, string> context = 2;
  string user_id = 3;
  string session_id = 4;
}

message ChatResponse {
  string response = 1;
  string message_id = 2;
  int64 timestamp = 3;
}

message StreamRequest {
  string message = 1;
  map<string, string> context = 2;
  string user_id = 3;
}

message StreamResponse {
  string content = 1;
  bool is_final = 2;
  string message_id = 3;
}

message HealthRequest {}

message HealthResponse {
  bool healthy = 1;
  string status = 2;
}
```

## Security Considerations

### Authentication & Authorization
- JWT token validation for WebSocket connections
- RBAC (Role-Based Access Control) for AI operations
- Rate limiting per user/session
- API key validation for service-to-service communication

### Data Protection
- Encrypted communication (TLS 1.3)
- Input sanitization and validation
- Context-based access control
- Audit logging for AI interactions

### Rate Limiting
- WebSocket: 100 messages per minute per user
- REST API: 60 requests per minute per user
- Streaming: 5 concurrent streams per user
- Global: 1000 requests per minute per service

## Error Handling

### Error Codes

#### WebSocket Error Codes
```go
const (
    ErrorCodeAIUnavailable     WebSocketErrorCode = 4001
    ErrorCodeAIMessageInvalid  WebSocketErrorCode = 4002
    ErrorCodeAIRateLimited     WebSocketErrorCode = 4003
    ErrorCodeAIContextInvalid  WebSocketErrorCode = 4004
)
```

#### HTTP Status Codes
- `400 Bad Request`: Invalid request format
- `401 Unauthorized`: Authentication required
- `429 Too Many Requests`: Rate limit exceeded
- `503 Service Unavailable`: AI service unavailable

### Error Response Format
```json
{
  "error": {
    "code": "AI_UNAVAILABLE",
    "message": "AI service is temporarily unavailable",
    "details": {
      "retry_after": 30,
      "service": "ai-copilot"
    }
  }
}
```

## Performance Optimizations

### Connection Pooling
- gRPC connection pool with 10 connections
- Connection health monitoring
- Automatic reconnection on failure
- Circuit breaker pattern implementation

### Caching Strategy
- Redis-based response caching
- Cache key: `ai_response:{user_id}:{message_hash}`
- TTL: 5 minutes for chat responses
- Cache invalidation on user context change

### Load Balancing
- Round-robin load balancing for AI service instances
- Health check-based routing
- Automatic failover to healthy instances
- Sticky sessions for streaming connections

## Testing Strategy

### Unit Tests
- Message validation tests
- gRPC client tests with mock server
- Error handling tests
- Rate limiting tests

### Integration Tests
- WebSocket connection tests
- AI service integration tests
- End-to-end chat flow tests
- Streaming response tests

### Load Tests
- Concurrent connection tests (1000+ connections)
- Message throughput tests (1000+ messages/second)
- AI service load tests
- Failover scenario tests

## Deployment Configuration

### Environment Variables
```bash
# AI Service Configuration
AI_SERVICE_HOST=ai-copilot-service
AI_SERVICE_PORT=50051
AI_SERVICE_TIMEOUT=30s

# Connection Pool
AI_CONNECTION_POOL_SIZE=10
AI_CONNECTION_TIMEOUT=5s

# Rate Limiting
AI_RATE_LIMIT_REQUESTS_PER_MINUTE=60
AI_RATE_LIMIT_STREAMS_PER_USER=5

# Cache Configuration
AI_CACHE_TTL=300s
REDIS_HOST=redis-service
REDIS_PORT=6379
```

### Docker Configuration
```yaml
# docker-compose.yml addition
services:
  ai-copilot:
    image: erp-ai-copilot:latest
    ports:
      - "50051:50051"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50051"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Monitoring & Observability

### Metrics Collection
- WebSocket connection count
- AI request/response latency
- Error rates by type
- Cache hit/miss ratios
- gRPC call success rates

### Logging Structure
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "level": "info",
  "service": "api-gateway",
  "component": "ai-handler",
  "event": "ai_chat_request",
  "user_id": "12345",
  "session_id": "sess_abc123",
  "message_length": 150,
  "response_time_ms": 1200,
  "status": "success"
}
```

### Health Checks
- AI service health endpoint
- gRPC connection health
- Cache connectivity
- WebSocket server status

## Usage Examples

### WebSocket Client Example
```javascript
// JavaScript WebSocket client
const ws = new WebSocket('wss://api.erp.com/ws');

ws.onopen = function() {
    // Send AI chat message
    ws.send(JSON.stringify({
        type: 'ai_chat',
        data: {
            message: 'Generate a sales report for Q1',
            context: { user_id: '12345', department: 'sales' }
        }
    }));
};

ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    if (message.type === 'ai_chat') {
        console.log('AI Response:', message.data.response);
    }
};
```

### REST API Client Example
```bash
# Send AI chat request via REST
curl -X POST https://api.erp.com/api/ai/chat \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "How are sales trending this month?",
    "context": {"department": "sales"}
  }'
```

### Go Client Example
```go
package main

import (
    "context"
    "log"
    "time"
    
    "google.golang.org/grpc"
    pb "path/to/ai/proto"
)

func main() {
    conn, err := grpc.Dial("ai-copilot-service:50051", grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    client := pb.NewAICopilotClient(conn)
    
    resp, err := client.Chat(context.Background(), &pb.ChatRequest{
        Message: "What's the revenue forecast?",
        Context: map[string]string{"department": "finance"},
        UserId:  "12345",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("AI Response: %s", resp.Response)
}
```

## Troubleshooting Guide

### Common Issues

#### WebSocket Connection Issues
- **Problem**: Connection closed immediately
- **Solution**: Check JWT token validity and user permissions

#### AI Service Unavailable
- **Problem**: 503 errors from AI service
- **Solution**: Verify AI service health and network connectivity

#### High Latency
- **Problem**: Slow AI responses (>5 seconds)
- **Solution**: Check cache hit rates and AI service load

#### Streaming Not Working
- **Problem**: No streaming responses received
- **Solution**: Verify WebSocket connection and streaming permissions

### Debug Commands
```bash
# Check AI service health
grpc_health_probe -addr=ai-copilot-service:50051

# Monitor WebSocket connections
netstat -an | grep :8080

# Check Redis cache
redis-cli KEYS "ai_response:*" | wc -l

# View recent logs
docker logs api-gateway | grep "ai-handler"
```

## Future Enhancements

### Planned Features
- Multi-language support
- Voice-to-text integration
- File upload for context
- Conversation history persistence
- AI model switching
- Custom AI training

### Performance Improvements
- Response streaming compression
- Intelligent caching
- Predictive pre-loading
- Edge caching deployment
- CDN integration

### Security Enhancements
- End-to-end encryption
- Advanced rate limiting
- DLP (Data Loss Prevention)
- Audit trail enhancement
- Compliance reporting

## Support & Maintenance

### Regular Tasks
- Monitor AI service performance
- Update security patches
- Review access logs
- Optimize cache settings
- Test failover scenarios

### Contact Information
- **Development Team**: dev-team@erp.com
- **AI Team**: ai-team@erp.com
- **Support**: support@erp.com

---

*Last Updated: January 2024*
*Version: 1.0.0*
*Document Owner: ERP Development Team*