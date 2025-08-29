package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/services/grpc_client"
	aipb "erp-api-gateway/proto/gen/ai/proto"
)

// Handler handles WebSocket connections and real-time messaging
type Handler struct {
	upgrader     websocket.Upgrader
	manager      interfaces.ConnectionManager
	redisClient  interfaces.PubSubService
	logger       interfaces.SimpleLogger
	jwtValidator interfaces.JWTValidator
	config       *config.WebSocketConfig
	subscription interfaces.PubSubSubscription
	grpcClient   *grpc_client.GRPCClient
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewHandler creates a new WebSocket handler
func NewHandler(
	cfg *config.WebSocketConfig,
	redisClient interfaces.PubSubService,
	logger interfaces.SimpleLogger,
	jwtValidator interfaces.JWTValidator,
	grpcClient *grpc_client.GRPCClient,
) *Handler {
	// Create WebSocket upgrader
	upgrader := websocket.Upgrader{
		ReadBufferSize:   cfg.ReadBufferSize,
		WriteBufferSize:  cfg.WriteBufferSize,
		HandshakeTimeout: cfg.HandshakeTimeout,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // Allow requests without Origin header
			}

			for _, allowedOrigin := range cfg.AllowedOrigins {
				if origin == allowedOrigin {
					return true
				}
			}
			return false
		},
		EnableCompression: cfg.EnableCompression,
	}

	// Create connection manager
	manager := NewManager(logger, cfg.MaxConnections)

	// Create context for the handler
	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		upgrader:     upgrader,
		manager:      manager,
		redisClient:  redisClient,
		logger:       logger,
		jwtValidator: jwtValidator,
		config:       cfg,
		grpcClient:   grpcClient,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Start Redis Pub/Sub listener
	go h.startRedisPubSubListener()

	return h
}

// HandleConnection handles WebSocket connection upgrades
func (h *Handler) HandleConnection(w http.ResponseWriter, r *http.Request) error {
	// Authenticate the WebSocket connection
	userID, err := h.authenticateConnection(r)
	if err != nil {
		h.logger.LogError(r.Context(), "WebSocket authentication failed", map[string]interface{}{
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.UserAgent(),
			"error":       err.Error(),
		})

		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return err
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.LogError(r.Context(), "WebSocket upgrade failed", map[string]interface{}{
			"user_id":     userID,
			"remote_addr": r.RemoteAddr,
			"error":       err.Error(),
		})
		return err
	}

	// Create connection config
	connConfig := ConnectionConfig{
		ReadTimeout:    h.config.ReadTimeout,
		WriteTimeout:   h.config.WriteTimeout,
		PongTimeout:    h.config.PongTimeout,
		PingPeriod:     h.config.PingPeriod,
		MaxMessageSize: h.config.MaxMessageSize,
	}

	// Create WebSocket connection wrapper
	wsConn := NewConnection(conn, userID, h.manager, h.logger, connConfig)

	// Add connection to manager
	if err := h.manager.AddConnection(wsConn); err != nil {
		h.logger.LogError(r.Context(), "Failed to add WebSocket connection", map[string]interface{}{
			"user_id":       userID,
			"connection_id": wsConn.GetID(),
			"error":         err.Error(),
		})

		wsConn.Close()
		return err
	}

	h.logger.LogInfo(r.Context(), "WebSocket connection established", map[string]interface{}{
		"user_id":       userID,
		"connection_id": wsConn.GetID(),
		"remote_addr":   r.RemoteAddr,
		"user_agent":    r.UserAgent(),
	})

	// Start connection pumps
	wsConn.Start(h.ctx)

	return nil
}

// BroadcastToUser broadcasts a message to all connections of a specific user
func (h *Handler) BroadcastToUser(ctx context.Context, userID string, message []byte) error {
	return h.manager.BroadcastToUser(ctx, userID, message)
}

// BroadcastToChannel broadcasts a message to all connections subscribed to a channel
func (h *Handler) BroadcastToChannel(ctx context.Context, channel string, message []byte) error {
	return h.manager.BroadcastToChannel(ctx, channel, message)
}

// GetConnectionCount returns the total number of active connections
func (h *Handler) GetConnectionCount() int {
	return h.manager.GetConnectionCount()
}

// ProcessAIChat processes an AI chat request via WebSocket using gRPC
func (h *Handler) ProcessAIChat(ctx context.Context, userID string, message string, conversationID string, agentType string, model string) (*aipb.ChatResponse, error) {
	// Get AI Copilot gRPC client
	aiClient, err := h.grpcClient.AICopilotService(ctx)
	if err != nil {
		h.logger.LogError(ctx, "Failed to get AI Copilot gRPC client", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to get AI Copilot gRPC client: %w", err)
	}

	// Create gRPC request
	req := &aipb.ChatRequest{
		Message:        message,
		UserId:         userID,
		ConversationId: conversationID,
		AgentType:      agentType,
		Model:          model,
		Temperature:    0.7,
		MaxTokens:      1000,
	}

	// Make gRPC call to AI service
	resp, err := aiClient.Chat(ctx, req)
	if err != nil {
		h.logger.LogError(ctx, "Failed to call AI Copilot gRPC service", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to call AI Copilot gRPC service: %w", err)
	}

	return resp, nil
}

// ProcessAIChatStream processes a streaming AI chat request via WebSocket using gRPC
func (h *Handler) ProcessAIChatStream(ctx context.Context, userID string, message string, conversationID string, agentType string, model string) (<-chan *aipb.ChatResponse, error) {
	// Get AI Copilot gRPC client
	aiClient, err := h.grpcClient.AICopilotService(ctx)
	if err != nil {
		h.logger.LogError(ctx, "Failed to get AI Copilot gRPC client", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to get AI Copilot gRPC client: %w", err)
	}

	// Create gRPC request
	req := &aipb.ChatRequest{
		Message:        message,
		UserId:         userID,
		ConversationId: conversationID,
		AgentType:      agentType,
		Model:          model,
		Temperature:    0.7,
		MaxTokens:      1000,
	}

	// Create response channel
	responseChan := make(chan *aipb.ChatResponse, 10)

	// Start streaming gRPC call
	go func() {
		defer close(responseChan)

		// Call the streaming gRPC method
		stream, err := aiClient.StreamChat(ctx, req)
		if err != nil {
			h.logger.LogError(ctx, "Failed to start streaming gRPC call", map[string]interface{}{
				"user_id": userID,
				"error":   err.Error(),
			})
			return
		}

		// Receive streaming responses
		for {
			resp, err := stream.Recv()
			if err != nil {
				// End of stream or error
				break
			}
			responseChan <- resp
		}
	}()

	return responseChan, nil
}

// GetHandler returns the handler instance for AI service access
func (h *Handler) GetHandler() *Handler {
	return h
}

// Close closes the WebSocket handler and all connections
func (h *Handler) Close() error {
	// Cancel context to stop all goroutines
	h.cancel()

	// Close Redis subscription
	if h.subscription != nil {
		if err := h.subscription.Close(); err != nil {
			h.logger.LogError(context.Background(), "Failed to close Redis subscription", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Close connection manager
	if err := h.manager.Close(); err != nil {
		h.logger.LogError(context.Background(), "Failed to close connection manager", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	h.logger.LogInfo(context.Background(), "WebSocket handler closed", nil)
	return nil
}

// authenticateConnection authenticates a WebSocket connection using JWT token
func (h *Handler) authenticateConnection(r *http.Request) (string, error) {
	// Try to get token from query parameter first (for WebSocket connections)
	token := r.URL.Query().Get("token")

	// If not in query, try Authorization header
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return "", fmt.Errorf("missing authentication token")
		}

		// Extract token from "Bearer <token>" format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return "", fmt.Errorf("invalid authorization header format")
		}
		token = parts[1]
	}

	if token == "" {
		return "", fmt.Errorf("empty authentication token")
	}

	// Validate JWT token
	claims, err := h.jwtValidator.ValidateToken(token)
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	if claims.UserID == "" {
		return "", fmt.Errorf("missing user ID in token claims")
	}

	return claims.UserID, nil
}

// startRedisPubSubListener starts listening to Redis Pub/Sub channels
func (h *Handler) startRedisPubSubListener() {
	// Subscribe to all notification channels and system broadcast
	channels := []string{
		"notifications:*",  // User-specific notifications
		"events:*",         // Event notifications
		"system:broadcast", // System-wide broadcasts
	}

	subscription, err := h.redisClient.Subscribe(h.ctx, channels...)
	if err != nil {
		h.logger.LogError(h.ctx, "Failed to subscribe to Redis channels", map[string]interface{}{
			"channels": channels,
			"error":    err.Error(),
		})
		return
	}

	h.subscription = subscription

	h.logger.LogInfo(h.ctx, "Started Redis Pub/Sub listener", map[string]interface{}{
		"channels": channels,
	})

	// Process incoming messages
	for {
		select {
		case <-h.ctx.Done():
			return
		case msg, ok := <-subscription.Channel():
			if !ok {
				h.logger.LogWarning(h.ctx, "Redis Pub/Sub channel closed", nil)
				return
			}

			if err := h.handleRedisMessage(msg); err != nil {
				h.logger.LogError(h.ctx, "Failed to handle Redis message", map[string]interface{}{
					"channel": msg.Channel,
					"error":   err.Error(),
				})
			}
		}
	}
}

// handleRedisMessage handles incoming Redis Pub/Sub messages
func (h *Handler) handleRedisMessage(msg *interfaces.Message) error {
	// Parse the message payload
	var wsMessage interfaces.WebSocketMessage
	if err := json.Unmarshal([]byte(msg.Payload), &wsMessage); err != nil {
		return fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// Set message ID if not present
	if wsMessage.MessageID == "" {
		wsMessage.MessageID = uuid.New().String()
	}

	// Set timestamp if not present
	if wsMessage.Timestamp.IsZero() {
		wsMessage.Timestamp = time.Now()
	}

	// Serialize message for WebSocket transmission
	messageBytes, err := json.Marshal(wsMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal WebSocket message: %w", err)
	}

	// Determine how to route the message based on channel
	if strings.HasPrefix(msg.Channel, "notifications:") {
		// User-specific notification
		userID := strings.TrimPrefix(msg.Channel, "notifications:")
		if userID != "" {
			return h.BroadcastToUser(h.ctx, userID, messageBytes)
		}
	} else if strings.HasPrefix(msg.Channel, "events:") {
		// Event-based notification - broadcast to channel
		return h.BroadcastToChannel(h.ctx, msg.Channel, messageBytes)
	} else if msg.Channel == "system:broadcast" {
		// System-wide broadcast - send to all connections
		return h.broadcastToAll(messageBytes)
	}

	h.logger.LogWarning(h.ctx, "Unknown Redis channel pattern", map[string]interface{}{
		"channel": msg.Channel,
	})

	return nil
}

// broadcastToAll broadcasts a message to all active connections
func (h *Handler) broadcastToAll(message []byte) error {
	// Get all connections and broadcast
	// This is a simplified implementation - in production, you might want to batch this
	connectionCount := h.manager.GetConnectionCount()

	h.logger.LogInfo(h.ctx, "Broadcasting to all connections", map[string]interface{}{
		"total_connections": connectionCount,
	})

	// For now, we'll use the system:broadcast channel
	return h.BroadcastToChannel(h.ctx, "system:broadcast", message)
}

// PublishNotification publishes a notification to Redis for real-time delivery
func (h *Handler) PublishNotification(ctx context.Context, userID string, notification map[string]interface{}) error {
	// Create WebSocket message
	wsMessage := &interfaces.WebSocketMessage{
		Type:      interfaces.MessageTypeNotification,
		Data:      notification,
		Timestamp: time.Now(),
		UserID:    userID,
		MessageID: uuid.New().String(),
	}

	// Publish to Redis channel
	channel := fmt.Sprintf("notifications:%s", userID)
	return h.redisClient.Publish(ctx, channel, wsMessage)
}

// PublishEvent publishes an event to Redis for real-time delivery
func (h *Handler) PublishEvent(ctx context.Context, eventType string, eventData map[string]interface{}) error {
	// Create WebSocket message
	wsMessage := &interfaces.WebSocketMessage{
		Type:      interfaces.MessageTypeEvent,
		Channel:   eventType,
		Data:      eventData,
		Timestamp: time.Now(),
		MessageID: uuid.New().String(),
	}

	// Publish to Redis channel
	channel := fmt.Sprintf("events:%s", eventType)
	return h.redisClient.Publish(ctx, channel, wsMessage)
}

// PublishSystemBroadcast publishes a system-wide broadcast message
func (h *Handler) PublishSystemBroadcast(ctx context.Context, message map[string]interface{}) error {
	// Create WebSocket message
	wsMessage := &interfaces.WebSocketMessage{
		Type:      interfaces.MessageTypeEvent,
		Channel:   "system:broadcast",
		Data:      message,
		Timestamp: time.Now(),
		MessageID: uuid.New().String(),
	}

	// Publish to Redis channel
	return h.redisClient.Publish(ctx, "system:broadcast", wsMessage)
}
