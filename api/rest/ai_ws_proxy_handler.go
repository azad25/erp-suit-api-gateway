package rest

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// AIWSProxyHandler proxies WebSocket connections to the AI Copilot service
type AIWSProxyHandler struct {
	targetURL string
	upgrader  websocket.Upgrader
}

// NewAIWSProxyHandler creates a new WebSocket proxy handler
func NewAIWSProxyHandler(targetBase string) (*AIWSProxyHandler, error) {
	// Validate target URL
	_, err := url.Parse(targetBase)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Allow all origins for WebSocket connections
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return &AIWSProxyHandler{
		targetURL: targetBase,
		upgrader:  upgrader,
	}, nil
}

// Proxy handles the WebSocket upgrade and proxies traffic to the AI service
func (h *AIWSProxyHandler) Proxy(c *gin.Context) {
	// Log the WebSocket proxy attempt
	fmt.Printf("WebSocket proxy request: %s %s\n", c.Request.Method, c.Request.URL.String())

	// Upgrade the HTTP connection to WebSocket
	clientConn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Printf("WebSocket upgrade failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to upgrade WebSocket connection",
			"error":   err.Error(),
		})
		return
	}
	defer clientConn.Close()

	// Build target WebSocket URL
	targetURL := fmt.Sprintf("%s/ws/chat", h.targetURL)

	// Add authentication token from query parameter or header
	query := c.Request.URL.Query()
	if token := query.Get("token"); token != "" {
		targetURL += "?token=" + token
		fmt.Printf("Using token from query parameter\n")
	} else if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		// Extract token from Authorization header if not in query
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token := authHeader[7:]
			targetURL += "?token=" + token
			fmt.Printf("Using token from Authorization header\n")
		}
	} else {
		// No token provided
		fmt.Printf("No authentication token provided\n")
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Authentication token required"))
		return
	}

	fmt.Printf("Connecting to target: %s\n", targetURL)

	// Connect to the AI Copilot WebSocket service
	serverConn, _, err := websocket.DefaultDialer.Dial(targetURL, nil)
	if err != nil {
		fmt.Printf("Failed to connect to AI service: %v\n", err)
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr,
				fmt.Sprintf("Failed to connect to AI service: %v", err)))
		return
	}
	defer serverConn.Close()

	fmt.Printf("WebSocket proxy connection established successfully\n")

	// Start proxying messages in both directions
	errChan := make(chan error, 2)

	// Client to Server
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("client to server proxy panic: %v", r)
			}
		}()
		errChan <- h.proxyMessages(clientConn, serverConn, "client->server")
	}()

	// Server to Client
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("server to client proxy panic: %v", r)
			}
		}()
		errChan <- h.proxyMessages(serverConn, clientConn, "server->client")
	}()

	// Wait for either direction to finish
	select {
	case err := <-errChan:
		if err != nil {
			// Log the error but don't send it to client as connection might be closed
			fmt.Printf("WebSocket proxy error: %v\n", err)
		}
	}
}

// proxyMessages copies messages from source to destination
func (h *AIWSProxyHandler) proxyMessages(src, dst *websocket.Conn, direction string) error {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				return fmt.Errorf("unexpected close in %s: %w", direction, err)
			}
			return nil // Normal close
		}

		err = dst.WriteMessage(messageType, message)
		if err != nil {
			return fmt.Errorf("failed to write message in %s: %w", direction, err)
		}
	}
}
