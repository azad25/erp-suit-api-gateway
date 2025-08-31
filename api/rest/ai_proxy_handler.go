package rest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AIProxyHandler handles AI Copilot related HTTP requests by proxying to the AI service
type AIProxyHandler struct {
	aiServiceURL string
	httpClient   *http.Client
}

// NewAIProxyHandler creates a new AI proxy handler
func NewAIProxyHandler(aiServiceURL string) *AIProxyHandler {
	return &AIProxyHandler{
		aiServiceURL: aiServiceURL,
		httpClient:   &http.Client{},
	}
}

// Chat handles chat requests by proxying to the AI service
func (h *AIProxyHandler) Chat(c *gin.Context) {
	// Read the request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to read request body",
			"details": err.Error(),
		})
		return
	}

	// Parse the request body to ensure model is set to Gemini
	var requestData map[string]interface{}
	if err := json.Unmarshal(body, &requestData); err == nil {
		// If model is not specified, set it to use Gemini
		if _, exists := requestData["model"]; !exists {
			requestData["model"] = "gemini2.0:flash"
			// Update the request body with the modified data
			body, _ = json.Marshal(requestData)
		}
	}

	// Create request to AI service
	req, err := http.NewRequest("POST", h.aiServiceURL+"/api/v1/chat/", bytes.NewBuffer(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "erp-api-gateway")
	// Forward auth header if present
	if auth := c.GetHeader("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	// Make request to AI service
	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to read AI service response",
			"details": err.Error(),
		})
		return
	}

	// Forward response status and body
	c.Data(resp.StatusCode, "application/json", respBody)
}

// StreamChat handles streaming chat requests by proxying to the AI service
func (h *AIProxyHandler) StreamChat(c *gin.Context) {
	// Read the request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to read request body",
			"details": err.Error(),
		})
		return
	}

	// Parse the request body to ensure model is set to Gemini
	var requestData map[string]interface{}
	if err := json.Unmarshal(body, &requestData); err == nil {
		// If model is not specified, set it to use Gemini
		if _, exists := requestData["model"]; !exists {
			requestData["model"] = "gemini2.0:flash"
			// Update the request body with the modified data
			body, _ = json.Marshal(requestData)
		}
	}

	// Create request to AI service
	// Stream endpoint on AI service
	req, err := http.NewRequest("POST", h.aiServiceURL+"/api/v1/chat/stream", bytes.NewBuffer(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "erp-api-gateway")
	// Forward auth header if present
	if auth := c.GetHeader("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	// Make request to AI service
	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// Forward content type from AI service (e.g., text/event-stream for SSE)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		c.Header("Content-Type", ct)
	} else {
		c.Header("Content-Type", "application/json")
	}
	// Forward status code
	c.Status(resp.StatusCode)

	// Stream body directly to the client with flushing
	if f, ok := c.Writer.(http.Flusher); ok {
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, wErr := c.Writer.Write(buf[:n]); wErr != nil {
					break
				}
				f.Flush()
			}
			if err != nil {
				break
			}
		}
		return
	}
	// Fallback: copy without explicit flushing
	io.Copy(c.Writer, resp.Body)
}

// HealthCheck handles AI service health check by proxying to the AI service
func (h *AIProxyHandler) HealthCheck(c *gin.Context) {
	// Create request to AI service
	req, err := http.NewRequest("GET", h.aiServiceURL+"/health", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy headers
	req.Header.Set("User-Agent", "erp-api-gateway")

	// Make request to AI service
	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to read AI service response",
			"details": err.Error(),
		})
		return
	}

	// Forward response status and body
	c.Data(resp.StatusCode, "application/json", respBody)
}

// Models handles AI models request by proxying to the AI service
func (h *AIProxyHandler) Models(c *gin.Context) {
	// Create request to AI service
	req, err := http.NewRequest("GET", h.aiServiceURL+"/models", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy headers
	req.Header.Set("User-Agent", "erp-api-gateway")

	// Make request to AI service
	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to read AI service response",
			"details": err.Error(),
		})
		return
	}

	// Forward response status and body
	c.Data(resp.StatusCode, "application/json", respBody)
}

// Query handles AI query requests by proxying to the AI service
func (h *AIProxyHandler) Query(c *gin.Context) {
	// Read the request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to read request body",
			"details": err.Error(),
		})
		return
	}

	// Parse the request body to ensure model is set to Gemini
	var requestData map[string]interface{}
	if err := json.Unmarshal(body, &requestData); err == nil {
		// If model is not specified, set it to use Gemini
		if _, exists := requestData["model"]; !exists {
			requestData["model"] = "gemini2.0:flash"
			// Update the request body with the modified data
			body, _ = json.Marshal(requestData)
		}
	}

	// Create request to AI service
	req, err := http.NewRequest("POST", h.aiServiceURL+"/query", bytes.NewBuffer(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "erp-api-gateway")
	// Forward auth header if present
	if auth := c.GetHeader("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	// Make request to AI service
	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to connect to AI service",
			"details": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to read AI service response",
			"details": err.Error(),
		})
		return
	}

	// Forward response status and body
	c.Data(resp.StatusCode, "application/json", respBody)
}
