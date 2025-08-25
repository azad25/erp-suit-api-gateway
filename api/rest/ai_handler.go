package rest

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"erp-api-gateway/internal/services/grpc_client"
	aipb "erp-api-gateway/proto/gen/ai/proto"
)

// AIHandler handles AI Copilot related HTTP requests
type AIHandler struct {
	grpcClient *grpc_client.GRPCClient
}

// NewAIHandler creates a new AI handler
func NewAIHandler(grpcClient *grpc_client.GRPCClient) *AIHandler {
	return &AIHandler{
		grpcClient: grpcClient,
	}
}

// Chat handles chat requests
func (h *AIHandler) Chat(c *gin.Context) {
	var req aipb.ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	client, err := h.grpcClient.AICopilotService(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}

	resp, err := client.Chat(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process chat",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// StreamChat handles streaming chat requests
func (h *AIHandler) StreamChat(c *gin.Context) {
	var req aipb.ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	client, err := h.grpcClient.AICopilotService(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}

	stream, err := client.StreamChat(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start chat stream",
			"details": err.Error(),
		})
		return
	}

	c.Header("Content-Type", "text/plain")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.SSEvent("error", gin.H{"error": err.Error()})
			c.Writer.Flush()
			return
		}
		
		c.SSEvent("message", gin.H{"response": resp.Content})
		c.Writer.Flush()
	}
}

// HealthCheck handles AI service health check
func (h *AIHandler) HealthCheck(c *gin.Context) {
	client, err := h.grpcClient.AICopilotService(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}

	req := &aipb.HealthCheckRequest{CheckType: "ai_copilot"}
	resp, err := client.HealthCheck(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "AI service health check failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}