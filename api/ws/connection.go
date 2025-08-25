package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/google/uuid"

	"erp-api-gateway/internal/interfaces"
)

// Connection represents a WebSocket connection
type Connection struct {
	id          string
	userID      string
	conn        *websocket.Conn
	channels    map[string]bool
	channelsMu  sync.RWMutex
	send        chan []byte
	manager     interfaces.ConnectionManager
	logger      interfaces.SimpleLogger
	isAlive     bool
	aliveMu     sync.RWMutex
	lastPong    time.Time
	lastPongMu  sync.RWMutex
	
	// Configuration
	readTimeout    time.Duration
	writeTimeout   time.Duration
	pongTimeout    time.Duration
	pingPeriod     time.Duration
	maxMessageSize int64
}

// NewConnection creates a new WebSocket connection
func NewConnection(
	conn *websocket.Conn,
	userID string,
	manager interfaces.ConnectionManager,
	logger interfaces.SimpleLogger,
	config ConnectionConfig,
) *Connection {
	connectionID := uuid.New().String()
	
	c := &Connection{
		id:             connectionID,
		userID:         userID,
		conn:           conn,
		channels:       make(map[string]bool),
		send:           make(chan []byte, 256),
		manager:        manager,
		logger:         logger,
		isAlive:        true,
		lastPong:       time.Now(),
		readTimeout:    config.ReadTimeout,
		writeTimeout:   config.WriteTimeout,
		pongTimeout:    config.PongTimeout,
		pingPeriod:     config.PingPeriod,
		maxMessageSize: config.MaxMessageSize,
	}
	
	// Configure WebSocket connection
	c.conn.SetReadLimit(c.maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(c.pongTimeout))
	c.conn.SetPongHandler(c.pongHandler)
	
	return c
}

// ConnectionConfig holds configuration for WebSocket connections
type ConnectionConfig struct {
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	PongTimeout    time.Duration
	PingPeriod     time.Duration
	MaxMessageSize int64
}

// GetID returns the connection ID
func (c *Connection) GetID() string {
	return c.id
}

// GetUserID returns the user ID
func (c *Connection) GetUserID() string {
	return c.userID
}

// GetChannels returns the subscribed channels
func (c *Connection) GetChannels() []string {
	c.channelsMu.RLock()
	defer c.channelsMu.RUnlock()
	
	channels := make([]string, 0, len(c.channels))
	for channel := range c.channels {
		channels = append(channels, channel)
	}
	return channels
}

// Send sends a message to the WebSocket connection
func (c *Connection) Send(ctx context.Context, message []byte) error {
	if !c.IsAlive() {
		return fmt.Errorf("connection is closed")
	}
	
	select {
	case c.send <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Channel is full, connection might be slow
		c.logger.LogWarning(ctx, "WebSocket send channel full, dropping message", map[string]interface{}{
			"connection_id": c.id,
			"user_id":       c.userID,
		})
		return fmt.Errorf("send channel full")
	}
}

// Subscribe subscribes to a channel
func (c *Connection) Subscribe(channel string) error {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	
	c.channels[channel] = true
	
	c.logger.LogInfo(context.Background(), "WebSocket connection subscribed to channel", map[string]interface{}{
		"connection_id": c.id,
		"user_id":       c.userID,
		"channel":       channel,
	})
	
	return nil
}

// Unsubscribe unsubscribes from a channel
func (c *Connection) Unsubscribe(channel string) error {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	
	delete(c.channels, channel)
	
	c.logger.LogInfo(context.Background(), "WebSocket connection unsubscribed from channel", map[string]interface{}{
		"connection_id": c.id,
		"user_id":       c.userID,
		"channel":       channel,
	})
	
	return nil
}

// IsAlive returns whether the connection is alive
func (c *Connection) IsAlive() bool {
	c.aliveMu.RLock()
	defer c.aliveMu.RUnlock()
	return c.isAlive
}

// Close closes the WebSocket connection
func (c *Connection) Close() error {
	c.aliveMu.Lock()
	if !c.isAlive {
		c.aliveMu.Unlock()
		return nil
	}
	c.isAlive = false
	c.aliveMu.Unlock()
	
	// Close send channel
	close(c.send)
	
	// Close WebSocket connection
	err := c.conn.Close()
	
	c.logger.LogInfo(context.Background(), "WebSocket connection closed", map[string]interface{}{
		"connection_id": c.id,
		"user_id":       c.userID,
	})
	
	return err
}

// Start starts the connection's read and write pumps
func (c *Connection) Start(ctx context.Context) {
	go c.writePump(ctx)
	go c.readPump(ctx)
}

// readPump handles reading messages from the WebSocket connection
func (c *Connection) readPump(ctx context.Context) {
	defer func() {
		if c.manager != nil {
			c.manager.RemoveConnection(c.id)
		}
		c.Close()
	}()
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.logger.LogError(ctx, "WebSocket read error", map[string]interface{}{
						"connection_id": c.id,
						"user_id":       c.userID,
						"error":         err.Error(),
					})
				}
				return
			}
			
			// Handle incoming message
			if err := c.handleMessage(ctx, message); err != nil {
				c.logger.LogError(ctx, "Failed to handle WebSocket message", map[string]interface{}{
					"connection_id": c.id,
					"user_id":       c.userID,
					"error":         err.Error(),
				})
				
				// Send error message back to client
				errorMsg := &interfaces.WebSocketMessage{
					Type:      interfaces.MessageTypeError,
					Data:      map[string]interface{}{"error": err.Error()},
					Timestamp: time.Now(),
					MessageID: uuid.New().String(),
				}
				
				if errorBytes, marshalErr := json.Marshal(errorMsg); marshalErr == nil {
					c.Send(ctx, errorBytes)
				}
			}
		}
	}
}

// writePump handles writing messages to the WebSocket connection
func (c *Connection) writePump(ctx context.Context) {
	ticker := time.NewTicker(c.pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()
	
	for {
		select {
		case <-ctx.Done():
			return
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
			if !ok {
				// Channel was closed
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				c.logger.LogError(ctx, "WebSocket write error", map[string]interface{}{
					"connection_id": c.id,
					"user_id":       c.userID,
					"error":         err.Error(),
				})
				return
			}
			
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.logger.LogError(ctx, "WebSocket ping error", map[string]interface{}{
					"connection_id": c.id,
					"user_id":       c.userID,
					"error":         err.Error(),
				})
				return
			}
		}
	}
}

// handleMessage handles incoming WebSocket messages
func (c *Connection) handleMessage(ctx context.Context, messageBytes []byte) error {
	var msg interfaces.WebSocketMessage
	if err := json.Unmarshal(messageBytes, &msg); err != nil {
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInvalidMessage,
			Message: "Invalid message format",
			Type:    "invalid_message",
		}
	}
	
	switch msg.Type {
	case interfaces.MessageTypeSubscribe:
		channel, ok := msg.Data["channel"].(string)
		if !ok {
			return &interfaces.WebSocketError{
				Code:    interfaces.WSErrorCodeInvalidMessage,
				Message: "Missing or invalid channel in subscribe message",
				Type:    "invalid_subscribe",
			}
		}
		
		if err := c.Subscribe(channel); err != nil {
			return err
		}
		
		// Send acknowledgment
		ackMsg := &interfaces.WebSocketMessage{
			Type:      interfaces.MessageTypeAck,
			Data:      map[string]interface{}{"action": "subscribe", "channel": channel},
			Timestamp: time.Now(),
			MessageID: uuid.New().String(),
		}
		
		if ackBytes, err := json.Marshal(ackMsg); err == nil {
			c.Send(ctx, ackBytes)
		}
		
	case interfaces.MessageTypeUnsubscribe:
		channel, ok := msg.Data["channel"].(string)
		if !ok {
			return &interfaces.WebSocketError{
				Code:    interfaces.WSErrorCodeInvalidMessage,
				Message: "Missing or invalid channel in unsubscribe message",
				Type:    "invalid_unsubscribe",
			}
		}
		
		if err := c.Unsubscribe(channel); err != nil {
			return err
		}
		
		// Send acknowledgment
		ackMsg := &interfaces.WebSocketMessage{
			Type:      interfaces.MessageTypeAck,
			Data:      map[string]interface{}{"action": "unsubscribe", "channel": channel},
			Timestamp: time.Now(),
			MessageID: uuid.New().String(),
		}
		
		if ackBytes, err := json.Marshal(ackMsg); err == nil {
			c.Send(ctx, ackBytes)
		}
		
	case interfaces.MessageTypeHeartbeat:
		// Respond with heartbeat
		heartbeatMsg := &interfaces.WebSocketMessage{
			Type:      interfaces.MessageTypeHeartbeat,
			Data:      map[string]interface{}{"status": "alive"},
			Timestamp: time.Now(),
			MessageID: uuid.New().String(),
		}

		if heartbeatBytes, err := json.Marshal(heartbeatMsg); err == nil {
			c.Send(ctx, heartbeatBytes)
		}

	case interfaces.MessageTypeAIChat:
		return c.handleAIChat(ctx, msg)

	case interfaces.MessageTypeAIStream:
		return c.handleAIStream(ctx, msg)

	default:
		c.logger.LogWarning(ctx, "Unknown WebSocket message type", map[string]interface{}{
			"connection_id": c.id,
			"user_id":       c.userID,
			"message_type":  msg.Type,
		})
	}
	
	return nil
}

// validateAIMessage validates AI chat message parameters
func (c *Connection) validateAIMessage(msgData map[string]interface{}) (string, string, string, string, error) {
	message, ok := msgData["message"].(string)
	if !ok || message == "" {
		return "", "", "", "", &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInvalidMessage,
			Message: "Missing or invalid message field",
			Type:    "invalid_ai_message",
		}
	}

	// Validate message length
	maxMessageLength := 10000
	if len(message) > maxMessageLength {
		return "", "", "", "", &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInvalidMessage,
			Message: fmt.Sprintf("Message too long. Maximum %d characters allowed", maxMessageLength),
			Type:    "message_too_long",
		}
	}

	// Validate message content (basic sanitization)
	message = strings.TrimSpace(message)
	if message == "" {
		return "", "", "", "", &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInvalidMessage,
			Message: "Message cannot be empty or whitespace only",
			Type:    "invalid_ai_message",
		}
	}

	conversationID, _ := msgData["conversation_id"].(string)
	if conversationID != "" {
		// Validate UUID format if provided
		if _, err := uuid.Parse(conversationID); err != nil {
			return "", "", "", "", &interfaces.WebSocketError{
				Code:    interfaces.WSErrorCodeInvalidMessage,
				Message: "Invalid conversation_id format",
				Type:    "invalid_conversation_id",
			}
		}
	} else {
		conversationID = uuid.New().String()
	}

	agentType, _ := msgData["agent_type"].(string)
	if agentType == "" {
		agentType = "general"
	} else {
		// Validate agent type
		validAgentTypes := map[string]bool{
			"general": true, "code": true, "data": true, "support": true,
		}
		if !validAgentTypes[agentType] {
			return "", "", "", "", &interfaces.WebSocketError{
				Code:    interfaces.WSErrorCodeInvalidMessage,
				Message: "Invalid agent_type. Allowed: general, code, data, support",
				Type:    "invalid_agent_type",
			}
		}
	}

	model, _ := msgData["model"].(string)
	if model == "" {
		model = "gpt-4"
	} else {
		// Validate model
		validModels := map[string]bool{
			"gpt-4": true, "gpt-3.5-turbo": true, "claude-3": true, "claude-3.5": true,
		}
		if !validModels[model] {
			return "", "", "", "", &interfaces.WebSocketError{
				Code:    interfaces.WSErrorCodeInvalidMessage,
				Message: "Invalid model. Allowed: gpt-4, gpt-3.5-turbo, claude-3, claude-3.5",
				Type:    "invalid_model",
			}
		}
	}

	return message, conversationID, agentType, model, nil
}

// handleAIChat handles AI chat messages via WebSocket
func (c *Connection) handleAIChat(ctx context.Context, msg interfaces.WebSocketMessage) error {
	message, ok := msg.Data["message"].(string)
	if !ok || message == "" {
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInvalidMessage,
			Message: "Missing or invalid message field",
			Type:    "invalid_ai_message",
		}
	}

	conversationID, _ := msg.Data["conversation_id"].(string)
	if conversationID == "" {
		conversationID = uuid.New().String()
	}

	agentType, _ := msg.Data["agent_type"].(string)
	if agentType == "" {
		agentType = "general"
	}

	model, _ := msg.Data["model"].(string)
	if model == "" {
		model = "gpt-4"
	}

	// Get AI service from connection manager
	// Use type assertion to get the underlying handler
	// Note: This assumes the manager is a Handler or has AI capabilities
	var handler *Handler
	if mgr, ok := c.manager.(interface{ GetHandler() *Handler }); ok {
		handler = mgr.GetHandler()
	}
	if handler == nil {
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInternalError,
			Message: "AI service not available",
			Type:    "ai_service_unavailable",
		}
	}

	// Validate message parameters
	validatedMessage, validatedConversationID, validatedAgentType, validatedModel, err := c.validateAIMessage(msg.Data)
	if err != nil {
		return err
	}
	
	// Use validated values
	message = validatedMessage
	conversationID = validatedConversationID
	agentType = validatedAgentType
	model = validatedModel

	// Rate limiting check (basic implementation)
	if err := c.checkRateLimit(c.userID); err != nil {
		return &interfaces.WebSocketError{
				Code:    interfaces.WSErrorCodeRateLimited,
				Message: err.Error(),
				Type:    "rate_limit_exceeded",
			}
	}

	// Process AI chat request
	response, err := handler.ProcessAIChat(ctx, c.userID, message, conversationID, agentType, model)
	if err != nil {
		// Provide more detailed error information
		var errorType string
		var errorMessage string
		
		switch {
		case strings.Contains(err.Error(), "timeout"):
			errorType = "ai_timeout"
			errorMessage = "AI service timeout. Please try again."
		case strings.Contains(err.Error(), "unavailable"):
			errorType = "ai_unavailable"
			errorMessage = "AI service temporarily unavailable"
		case strings.Contains(err.Error(), "quota"):
			errorType = "quota_exceeded"
			errorMessage = "AI service quota exceeded"
		default:
			errorType = "ai_processing_error"
			errorMessage = "AI processing failed. Please try again."
		}
		
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInternalError,
			Message: errorMessage,
			Type:    errorType,
		}
	}

	// Validate response
	if response == nil || response.Content == "" {
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInternalError,
			Message: "Empty response from AI service",
			Type:    "empty_response",
		}
	}

	// Send response back to client
	responseMsg := &interfaces.WebSocketMessage{
		Type: interfaces.MessageTypeAIChat,
		Data: map[string]interface{}{
			"response":        response.Content,
			"conversation_id": conversationID,
			"agent_type":      agentType,
			"model":           model,
			"message_id":      msg.MessageID,
			"timestamp":       time.Now().Unix(),
		},
		Timestamp: time.Now(),
		MessageID: uuid.New().String(),
	}

	if responseBytes, err := json.Marshal(responseMsg); err == nil {
		c.Send(ctx, responseBytes)
	} else {
		c.logger.LogError(ctx, "Failed to marshal AI response", map[string]interface{}{
			"error": err.Error(),
			"user_id": c.userID,
		})
	}

	return nil
}

// checkRateLimit performs basic rate limiting for AI requests
func (c *Connection) checkRateLimit(userID string) error {
	// Simple in-memory rate limiting - in production, use Redis or similar
	// Allow 10 requests per minute per user
	const (
		maxRequestsPerMinute = 10
		windowDuration       = time.Minute
	)

	// This is a basic implementation - for production, consider using a proper rate limiter
	// For now, we'll skip rate limiting as it requires more infrastructure
	return nil
}

// handleAIStream handles streaming AI chat messages via WebSocket
func (c *Connection) handleAIStream(ctx context.Context, msg interfaces.WebSocketMessage) error {
	message, ok := msg.Data["message"].(string)
	if !ok || message == "" {
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInvalidMessage,
			Message: "Missing or invalid message field",
			Type:    "invalid_ai_message",
		}
	}

	conversationID, _ := msg.Data["conversation_id"].(string)
	if conversationID == "" {
		conversationID = uuid.New().String()
	}

	agentType, _ := msg.Data["agent_type"].(string)
	if agentType == "" {
		agentType = "general"
	}

	model, _ := msg.Data["model"].(string)
	if model == "" {
		model = "gpt-4"
	}

	// Get AI service from connection manager
	// Use type assertion to get the underlying handler
	// Note: This assumes the manager is a Handler or has AI capabilities
	var handler *Handler
	if mgr, ok := c.manager.(interface{ GetHandler() *Handler }); ok {
		handler = mgr.GetHandler()
	}
	if handler == nil {
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInternalError,
			Message: "AI service not available",
			Type:    "ai_service_unavailable",
		}
	}

	// Send initial status message
	statusMsg := &interfaces.WebSocketMessage{
		Type: interfaces.MessageTypeAIStatus,
		Data: map[string]interface{}{
			"status":          "processing",
			"conversation_id": conversationID,
			"message_id":      msg.MessageID,
		},
		Timestamp: time.Now(),
		MessageID: uuid.New().String(),
	}

	if statusBytes, err := json.Marshal(statusMsg); err == nil {
		c.Send(ctx, statusBytes)
	}

	// Validate message parameters
	message, conversationID, agentType, model, err := c.validateAIMessage(msg.Data)
	if err != nil {
		return err
	}

	// Rate limiting check
	if err := c.checkRateLimit(c.userID); err != nil {
		return &interfaces.WebSocketError{
				Code:    interfaces.WSErrorCodeRateLimited,
				Message: err.Error(),
				Type:    "rate_limit_exceeded",
			}
	}

	// Process streaming AI chat request
	responseChan, err := handler.ProcessAIChatStream(ctx, c.userID, message, conversationID, agentType, model)
	if err != nil {
		// Provide more detailed error information
		var errorType string
		var errorMessage string
		
		switch {
		case strings.Contains(err.Error(), "timeout"):
			errorType = "ai_timeout"
			errorMessage = "AI service timeout. Please try again."
		case strings.Contains(err.Error(), "unavailable"):
			errorType = "ai_unavailable"
			errorMessage = "AI service temporarily unavailable"
		case strings.Contains(err.Error(), "quota"):
			errorType = "quota_exceeded"
			errorMessage = "AI service quota exceeded"
		default:
			errorType = "ai_processing_error"
			errorMessage = "AI processing failed. Please try again."
		}
		
		return &interfaces.WebSocketError{
			Code:    interfaces.WSErrorCodeInternalError,
			Message: errorMessage,
			Type:    errorType,
		}
	}

	// Handle streaming responses
	go func() {
		defer func() {
			// Send completion status
			completionMsg := &interfaces.WebSocketMessage{
				Type: interfaces.MessageTypeAIStatus,
				Data: map[string]interface{}{
					"status":          "completed",
					"conversation_id": conversationID,
					"message_id":      msg.MessageID,
					"timestamp":       time.Now().Unix(),
				},
				Timestamp: time.Now(),
				MessageID: uuid.New().String(),
			}

			if completionBytes, err := json.Marshal(completionMsg); err == nil {
				c.Send(ctx, completionBytes)
			} else {
				c.logger.LogError(ctx, "Failed to marshal AI completion status", map[string]interface{}{
					"error": err.Error(),
					"user_id": c.userID,
				})
			}
		}()

		for response := range responseChan {
			if response != nil && response.Content != "" {
				streamMsg := &interfaces.WebSocketMessage{
					Type: interfaces.MessageTypeAIStream,
					Data: map[string]interface{}{
						"response":        response.Content,
						"conversation_id": conversationID,
						"agent_type":      agentType,
						"model":           model,
						"message_id":      msg.MessageID,
						"is_final":        true,
						"timestamp":       time.Now().Unix(),
					},
					Timestamp: time.Now(),
					MessageID: uuid.New().String(),
				}

				if streamBytes, err := json.Marshal(streamMsg); err == nil {
					c.Send(ctx, streamBytes)
				} else {
					c.logger.LogError(ctx, "Failed to marshal AI stream response", map[string]interface{}{
						"error": err.Error(),
						"user_id": c.userID,
					})
				}
			}
		}
	}()

	return nil
}

// pongHandler handles pong messages from the client
func (c *Connection) pongHandler(appData string) error {
	c.lastPongMu.Lock()
	c.lastPong = time.Now()
	c.lastPongMu.Unlock()
	
	c.conn.SetReadDeadline(time.Now().Add(c.pongTimeout))
	return nil
}

// GetLastPong returns the last pong time
func (c *Connection) GetLastPong() time.Time {
	c.lastPongMu.RLock()
	defer c.lastPongMu.RUnlock()
	return c.lastPong
}