package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// WebSocketProxy handles proxying WebSocket connections to the WebSocket Server
type WebSocketProxy struct {
	config   *config.WebSocketConfig
	upgrader websocket.Upgrader
	logger   interfaces.SimpleLogger
}

// NewWebSocketProxy creates a new WebSocket proxy
func NewWebSocketProxy(config *config.WebSocketConfig, logger interfaces.SimpleLogger) *WebSocketProxy {
	return &WebSocketProxy{
		config: config,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return config.EnableCORS // Allow all origins if CORS is enabled
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		logger: logger,
	}
}

// ProxyConnection proxies a WebSocket connection to the WebSocket Server
func (p *WebSocketProxy) ProxyConnection(c *gin.Context) {
	// Upgrade the HTTP connection to WebSocket
	clientConn, err := p.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		p.logger.LogError(c.Request.Context(), "Failed to upgrade WebSocket connection", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	defer clientConn.Close()

	// Create connection to the WebSocket Server
	targetURL := url.URL{
		Scheme: "ws",
		Host:   fmt.Sprintf("%s:%d", p.config.ServerHost, p.config.ServerPort),
		Path:   p.config.Endpoint,
	}

	// Add authentication parameters if available
	query := url.Values{}
	if token := c.GetHeader("Authorization"); token != "" {
		query.Set("token", token)
	}
	if userID, exists := c.Get("user_id"); exists {
		query.Set("user_id", userID.(string))
	}
	if orgID, exists := c.Get("organization_id"); exists {
		query.Set("organization_id", orgID.(string))
	}
	targetURL.RawQuery = query.Encode()

	// Connect to the WebSocket Server
	serverConn, _, err := websocket.DefaultDialer.Dial(targetURL.String(), nil)
	if err != nil {
		p.logger.LogError(c.Request.Context(), "Failed to connect to WebSocket server", map[string]interface{}{
			"error": err.Error(),
			"target_url": targetURL.String(),
		})
		clientConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "WebSocket service unavailable"))
		return
	}
	defer serverConn.Close()

	p.logger.LogInfo(c.Request.Context(), "WebSocket proxy connection established", map[string]interface{}{
		"target_url": targetURL.String(),
	})

	// Start proxying messages in both directions
	errChan := make(chan error, 2)

	// Client to Server
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("client to server proxy panic: %v", r)
			}
		}()
		errChan <- p.proxyMessages(clientConn, serverConn, "client->server")
	}()

	// Server to Client
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("server to client proxy panic: %v", r)
			}
		}()
		errChan <- p.proxyMessages(serverConn, clientConn, "server->client")
	}()

	// Wait for either direction to close or error
	err = <-errChan
	if err != nil {
		p.logger.LogError(c.Request.Context(), "WebSocket proxy error", map[string]interface{}{
			"error": err.Error(),
		})
	}

	p.logger.LogInfo(c.Request.Context(), "WebSocket proxy connection closed", map[string]interface{}{
		"target_url": targetURL.String(),
	})
}

// proxyMessages proxies messages from source to destination
func (p *WebSocketProxy) proxyMessages(src, dst *websocket.Conn, direction string) error {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				return fmt.Errorf("websocket read error (%s): %v", direction, err)
			}
			return nil // Normal close
		}

		err = dst.WriteMessage(messageType, message)
		if err != nil {
			return fmt.Errorf("websocket write error (%s): %v", direction, err)
		}
	}
}