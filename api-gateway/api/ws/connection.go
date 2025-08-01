package ws

import (
	"context"
	"encoding/json"
	"fmt"
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
		
	default:
		c.logger.LogWarning(ctx, "Unknown WebSocket message type", map[string]interface{}{
			"connection_id": c.id,
			"user_id":       c.userID,
			"message_type":  msg.Type,
		})
	}
	
	return nil
}

// pongHandler handles pong messages from the client
func (c *Connection) pongHandler(string) error {
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