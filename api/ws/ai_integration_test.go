package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"erp-api-gateway/internal/interfaces"
)

// TestWebSocketAIIntegration provides basic test structure for AI Copilot WebSocket integration
// This is a demonstration test file - actual testing requires a running AI service

func TestWebSocketAIIntegration(t *testing.T) {
	// Setup test dependencies
	_ = context.Background()
	
	// Create test WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This would normally be handled by the actual WebSocket handler
		// For testing purposes, we'll create a simple echo server
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Simple echo for demonstration
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}
			
			var wsMsg interfaces.WebSocketMessage
			if err := json.Unmarshal(message, &wsMsg); err != nil {
				continue
			}

			// Echo back for testing
			conn.WriteMessage(websocket.TextMessage, message)
		}
	}))
	defer server.Close()

	// Test cases
	tests := []struct {
		name     string
		message  interfaces.WebSocketMessage
		wantType string
		wantErr  bool
	}{
		{
			name: "Valid AI Chat Message",
			message: interfaces.WebSocketMessage{
				Type: interfaces.MessageTypeAIChat,
				Data: map[string]interface{}{
					"message": "Hello AI assistant",
					"agent_type": "general",
					"model": "gpt-4",
				},
				MessageID: uuid.New().String(),
			},
			wantType: string(interfaces.MessageTypeAIChat),
			wantErr:  false,
		},
		{
			name: "Valid AI Stream Message",
			message: interfaces.WebSocketMessage{
				Type: interfaces.MessageTypeAIStream,
				Data: map[string]interface{}{
					"message": "Tell me a story",
					"agent_type": "general",
					"model": "gpt-4",
				},
				MessageID: uuid.New().String(),
			},
			wantType: string(interfaces.MessageTypeAIStatus),
			wantErr:  false,
		},
		{
			name: "Invalid Message - Missing message field",
			message: interfaces.WebSocketMessage{
				Type: interfaces.MessageTypeAIChat,
				Data: map[string]interface{}{
					"agent_type": "general",
				},
				MessageID: uuid.New().String(),
			},
			wantType: string(interfaces.MessageTypeError),
			wantErr:  true,
		},
		{
			name: "Invalid Message - Too long",
			message: interfaces.WebSocketMessage{
				Type: interfaces.MessageTypeAIChat,
				Data: map[string]interface{}{
					"message": strings.Repeat("a", 11000),
					"agent_type": "general",
				},
				MessageID: uuid.New().String(),
			},
			wantType: string(interfaces.MessageTypeError),
			wantErr:  true,
		},
		{
			name: "Invalid Agent Type",
			message: interfaces.WebSocketMessage{
				Type: interfaces.MessageTypeAIChat,
				Data: map[string]interface{}{
					"message": "Hello",
					"agent_type": "invalid_agent",
				},
				MessageID: uuid.New().String(),
			},
			wantType: string(interfaces.MessageTypeError),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert server URL to WebSocket URL
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

			// Connect to WebSocket
			conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatalf("Failed to connect to WebSocket: %v", err)
			}
			defer conn.Close()
			defer resp.Body.Close()

			// Send test message
			messageBytes, err := json.Marshal(tt.message)
			if err != nil {
				t.Fatalf("Failed to marshal message: %v", err)
			}

			err = conn.WriteMessage(websocket.TextMessage, messageBytes)
			if err != nil {
				t.Fatalf("Failed to write message: %v", err)
			}

			// Read response
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, response, err := conn.ReadMessage()
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				var respMsg interfaces.WebSocketMessage
				if err := json.Unmarshal(response, &respMsg); err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
					return
				}

				if respMsg.Type != tt.wantType {
					t.Errorf("Expected message type %s, got %s", tt.wantType, respMsg.Type)
				}
			}
		})
	}
}

// TestAIMessageValidation tests the message validation functions
func TestAIMessageValidation(t *testing.T) {
	// Create a mock connection for testing
	conn := &Connection{
		userID: "test-user",
		logger: &mockLogger{},
	}

	tests := []struct {
		name        string
		data        map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid message",
			data: map[string]interface{}{
				"message": "Hello AI",
				"agent_type": "general",
				"model": "gpt-4",
			},
			wantErr: false,
		},
		{
			name: "Missing message",
			data: map[string]interface{}{
				"agent_type": "general",
			},
			wantErr:     true,
		errContains: "Missing or invalid message field",
		},
		{
			name: "Empty message",
			data: map[string]interface{}{
				"message": "",
				"agent_type": "general",
			},
			wantErr:     true,
		errContains: "Missing or invalid message field",
		},
		{
			name: "Message too long",
			data: map[string]interface{}{
				"message": strings.Repeat("a", 11000),
				"agent_type": "general",
			},
			wantErr:     true,
		errContains: "Message too long",
		},
		{
			name: "Invalid agent type",
			data: map[string]interface{}{
				"message": "Hello",
				"agent_type": "invalid",
			},
			wantErr:     true,
		errContains: "Invalid agent_type",
		},
		{
			name: "Invalid model",
			data: map[string]interface{}{
				"message": "Hello",
				"model": "invalid-model",
			},
			wantErr:     true,
		errContains: "Invalid model",
		},
		{
			name: "Invalid conversation ID format",
			data: map[string]interface{}{
				"message": "Hello",
				"conversation_id": "invalid-uuid",
			},
			wantErr:     true,
		errContains: "Invalid conversation_id format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := conn.validateAIMessage(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAIMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateAIMessage() error = %v, should contain %v", err, tt.errContains)
				}
			}
		})
	}
}

// mockLogger is a simple mock for testing
type mockLogger struct{}

func (m *mockLogger) LogInfo(ctx context.Context, message string, fields map[string]interface{}) {}
func (m *mockLogger) LogError(ctx context.Context, message string, fields map[string]interface{}) {}
func (m *mockLogger) LogWarning(ctx context.Context, message string, fields map[string]interface{}) {}

// Example usage documentation
/*

To test the WebSocket AI integration:

1. Start the API Gateway service:
   go run cmd/main.go

2. Connect to WebSocket endpoint:
   ws://localhost:8080/ws

3. Send AI chat message:
   {
     "type": "ai_chat",
     "message_id": "uuid-here",
     "data": {
       "message": "Hello, can you help me?",
       "agent_type": "general",
       "model": "gpt-4",
       "conversation_id": "optional-uuid"
     }
   }

4. Send AI stream message:
   {
     "type": "ai_stream",
     "message_id": "uuid-here",
     "data": {
       "message": "Tell me a story",
       "agent_type": "general",
       "model": "gpt-4"
     }
   }

Expected responses:
- AI chat: Single response with full answer
- AI stream: Multiple streaming responses with "processing", "streaming", and "completed" status messages

*/