package ws

import (
	"context"
	"fmt"
	"sync"
	"time"

	"erp-api-gateway/internal/interfaces"
)

// Manager manages WebSocket connections
type Manager struct {
	connections       map[string]interfaces.WebSocketConnection
	connectionsMu     sync.RWMutex
	userConnections   map[string]map[string]bool // userID -> connectionID -> bool
	userConnectionsMu sync.RWMutex
	channelConnections map[string]map[string]bool // channel -> connectionID -> bool
	channelConnectionsMu sync.RWMutex
	logger            interfaces.SimpleLogger
	maxConnections    int
	cleanupInterval   time.Duration
	stopCleanup       chan struct{}
}

// NewManager creates a new connection manager
func NewManager(logger interfaces.SimpleLogger, maxConnections int) *Manager {
	m := &Manager{
		connections:        make(map[string]interfaces.WebSocketConnection),
		userConnections:    make(map[string]map[string]bool),
		channelConnections: make(map[string]map[string]bool),
		logger:             logger,
		maxConnections:     maxConnections,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}
	
	// Start cleanup goroutine
	go m.cleanupRoutine()
	
	return m
}

// AddConnection adds a new WebSocket connection
func (m *Manager) AddConnection(conn interfaces.WebSocketConnection) error {
	m.connectionsMu.Lock()
	defer m.connectionsMu.Unlock()
	
	// Check connection limit
	if len(m.connections) >= m.maxConnections {
		return fmt.Errorf("maximum connections reached: %d", m.maxConnections)
	}
	
	connectionID := conn.GetID()
	userID := conn.GetUserID()
	
	// Add to connections map
	m.connections[connectionID] = conn
	
	// Add to user connections map
	m.userConnectionsMu.Lock()
	if m.userConnections[userID] == nil {
		m.userConnections[userID] = make(map[string]bool)
	}
	m.userConnections[userID][connectionID] = true
	m.userConnectionsMu.Unlock()
	
	// Subscribe to user-specific notification channel
	userChannel := fmt.Sprintf("notifications:%s", userID)
	if err := conn.Subscribe(userChannel); err != nil {
		m.logger.LogError(context.Background(), "Failed to subscribe to user channel", map[string]interface{}{
			"connection_id": connectionID,
			"user_id":       userID,
			"channel":       userChannel,
			"error":         err.Error(),
		})
	}
	
	// Update channel connections
	m.updateChannelConnections(connectionID, []string{userChannel}, []string{})
	
	m.logger.LogInfo(context.Background(), "WebSocket connection added", map[string]interface{}{
		"connection_id":    connectionID,
		"user_id":          userID,
		"total_connections": len(m.connections),
	})
	
	return nil
}

// RemoveConnection removes a WebSocket connection
func (m *Manager) RemoveConnection(connectionID string) error {
	m.connectionsMu.Lock()
	conn, exists := m.connections[connectionID]
	if !exists {
		m.connectionsMu.Unlock()
		return fmt.Errorf("connection not found: %s", connectionID)
	}
	
	userID := conn.GetUserID()
	channels := conn.GetChannels()
	
	// Remove from connections map
	delete(m.connections, connectionID)
	m.connectionsMu.Unlock()
	
	// Remove from user connections map
	m.userConnectionsMu.Lock()
	if userConns, exists := m.userConnections[userID]; exists {
		delete(userConns, connectionID)
		if len(userConns) == 0 {
			delete(m.userConnections, userID)
		}
	}
	m.userConnectionsMu.Unlock()
	
	// Remove from channel connections
	m.updateChannelConnections(connectionID, []string{}, channels)
	
	m.logger.LogInfo(context.Background(), "WebSocket connection removed", map[string]interface{}{
		"connection_id":     connectionID,
		"user_id":           userID,
		"remaining_connections": len(m.connections),
	})
	
	return nil
}

// GetConnection retrieves a WebSocket connection by ID
func (m *Manager) GetConnection(connectionID string) (interfaces.WebSocketConnection, bool) {
	m.connectionsMu.RLock()
	defer m.connectionsMu.RUnlock()
	
	conn, exists := m.connections[connectionID]
	return conn, exists
}

// GetUserConnections retrieves all connections for a user
func (m *Manager) GetUserConnections(userID string) []interfaces.WebSocketConnection {
	m.userConnectionsMu.RLock()
	connectionIDs, exists := m.userConnections[userID]
	if !exists {
		m.userConnectionsMu.RUnlock()
		return []interfaces.WebSocketConnection{}
	}
	
	// Copy connection IDs to avoid holding the lock while accessing connections
	ids := make([]string, 0, len(connectionIDs))
	for id := range connectionIDs {
		ids = append(ids, id)
	}
	m.userConnectionsMu.RUnlock()
	
	// Get connections
	m.connectionsMu.RLock()
	defer m.connectionsMu.RUnlock()
	
	connections := make([]interfaces.WebSocketConnection, 0, len(ids))
	for _, id := range ids {
		if conn, exists := m.connections[id]; exists && conn.IsAlive() {
			connections = append(connections, conn)
		}
	}
	
	return connections
}

// GetChannelConnections retrieves all connections subscribed to a channel
func (m *Manager) GetChannelConnections(channel string) []interfaces.WebSocketConnection {
	m.channelConnectionsMu.RLock()
	connectionIDs, exists := m.channelConnections[channel]
	if !exists {
		m.channelConnectionsMu.RUnlock()
		return []interfaces.WebSocketConnection{}
	}
	
	// Copy connection IDs to avoid holding the lock while accessing connections
	ids := make([]string, 0, len(connectionIDs))
	for id := range connectionIDs {
		ids = append(ids, id)
	}
	m.channelConnectionsMu.RUnlock()
	
	// Get connections
	m.connectionsMu.RLock()
	defer m.connectionsMu.RUnlock()
	
	connections := make([]interfaces.WebSocketConnection, 0, len(ids))
	for _, id := range ids {
		if conn, exists := m.connections[id]; exists && conn.IsAlive() {
			connections = append(connections, conn)
		}
	}
	
	return connections
}

// BroadcastToUser broadcasts a message to all connections of a specific user
func (m *Manager) BroadcastToUser(ctx context.Context, userID string, message []byte) error {
	connections := m.GetUserConnections(userID)
	
	if len(connections) == 0 {
		m.logger.LogInfo(ctx, "No active connections for user", map[string]interface{}{
			"user_id": userID,
		})
		return nil
	}
	
	var errors []error
	successCount := 0
	
	for _, conn := range connections {
		if err := conn.Send(ctx, message); err != nil {
			errors = append(errors, fmt.Errorf("failed to send to connection %s: %w", conn.GetID(), err))
			m.logger.LogError(ctx, "Failed to send message to connection", map[string]interface{}{
				"connection_id": conn.GetID(),
				"user_id":       userID,
				"error":         err.Error(),
			})
		} else {
			successCount++
		}
	}
	
	m.logger.LogInfo(ctx, "Broadcast to user completed", map[string]interface{}{
		"user_id":        userID,
		"total_connections": len(connections),
		"successful_sends":  successCount,
		"failed_sends":      len(errors),
	})
	
	if len(errors) > 0 && successCount == 0 {
		return fmt.Errorf("failed to send to all connections for user %s", userID)
	}
	
	return nil
}

// BroadcastToChannel broadcasts a message to all connections subscribed to a channel
func (m *Manager) BroadcastToChannel(ctx context.Context, channel string, message []byte) error {
	connections := m.GetChannelConnections(channel)
	
	if len(connections) == 0 {
		m.logger.LogInfo(ctx, "No active connections for channel", map[string]interface{}{
			"channel": channel,
		})
		return nil
	}
	
	var errors []error
	successCount := 0
	
	for _, conn := range connections {
		if err := conn.Send(ctx, message); err != nil {
			errors = append(errors, fmt.Errorf("failed to send to connection %s: %w", conn.GetID(), err))
			m.logger.LogError(ctx, "Failed to send message to connection", map[string]interface{}{
				"connection_id": conn.GetID(),
				"user_id":       conn.GetUserID(),
				"channel":       channel,
				"error":         err.Error(),
			})
		} else {
			successCount++
		}
	}
	
	m.logger.LogInfo(ctx, "Broadcast to channel completed", map[string]interface{}{
		"channel":           channel,
		"total_connections": len(connections),
		"successful_sends":  successCount,
		"failed_sends":      len(errors),
	})
	
	if len(errors) > 0 && successCount == 0 {
		return fmt.Errorf("failed to send to all connections for channel %s", channel)
	}
	
	return nil
}

// GetConnectionCount returns the total number of active connections
func (m *Manager) GetConnectionCount() int {
	m.connectionsMu.RLock()
	defer m.connectionsMu.RUnlock()
	return len(m.connections)
}

// GetUserCount returns the total number of users with active connections
func (m *Manager) GetUserCount() int {
	m.userConnectionsMu.RLock()
	defer m.userConnectionsMu.RUnlock()
	return len(m.userConnections)
}

// Close closes the connection manager and all connections
func (m *Manager) Close() error {
	// Stop cleanup routine
	close(m.stopCleanup)
	
	// Close all connections
	m.connectionsMu.Lock()
	connections := make([]interfaces.WebSocketConnection, 0, len(m.connections))
	for _, conn := range m.connections {
		connections = append(connections, conn)
	}
	m.connections = make(map[string]interfaces.WebSocketConnection)
	m.connectionsMu.Unlock()
	
	// Clear other maps
	m.userConnectionsMu.Lock()
	m.userConnections = make(map[string]map[string]bool)
	m.userConnectionsMu.Unlock()
	
	m.channelConnectionsMu.Lock()
	m.channelConnections = make(map[string]map[string]bool)
	m.channelConnectionsMu.Unlock()
	
	// Close all connections
	for _, conn := range connections {
		if err := conn.Close(); err != nil {
			m.logger.LogError(context.Background(), "Failed to close connection", map[string]interface{}{
				"connection_id": conn.GetID(),
				"error":         err.Error(),
			})
		}
	}
	
	m.logger.LogInfo(context.Background(), "Connection manager closed", map[string]interface{}{
		"closed_connections": len(connections),
	})
	
	return nil
}

// updateChannelConnections updates the channel connections mapping
func (m *Manager) updateChannelConnections(connectionID string, addChannels, removeChannels []string) {
	m.channelConnectionsMu.Lock()
	defer m.channelConnectionsMu.Unlock()
	
	// Add to channels
	for _, channel := range addChannels {
		if m.channelConnections[channel] == nil {
			m.channelConnections[channel] = make(map[string]bool)
		}
		m.channelConnections[channel][connectionID] = true
	}
	
	// Remove from channels
	for _, channel := range removeChannels {
		if channelConns, exists := m.channelConnections[channel]; exists {
			delete(channelConns, connectionID)
			if len(channelConns) == 0 {
				delete(m.channelConnections, channel)
			}
		}
	}
}

// cleanupRoutine periodically cleans up dead connections
func (m *Manager) cleanupRoutine() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.cleanupDeadConnections()
		}
	}
}

// cleanupDeadConnections removes dead connections
func (m *Manager) cleanupDeadConnections() {
	m.connectionsMu.RLock()
	deadConnections := make([]string, 0)
	
	for id, conn := range m.connections {
		if !conn.IsAlive() {
			deadConnections = append(deadConnections, id)
		}
	}
	m.connectionsMu.RUnlock()
	
	// Remove dead connections
	for _, id := range deadConnections {
		if err := m.RemoveConnection(id); err != nil {
			m.logger.LogError(context.Background(), "Failed to remove dead connection", map[string]interface{}{
				"connection_id": id,
				"error":         err.Error(),
			})
		}
	}
	
	if len(deadConnections) > 0 {
		m.logger.LogInfo(context.Background(), "Cleaned up dead connections", map[string]interface{}{
			"cleaned_connections": len(deadConnections),
			"remaining_connections": m.GetConnectionCount(),
		})
	}
}