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

// CreateConversation handles conversation creation by proxying to the AI service
func (h *AIProxyHandler) CreateConversation(c *gin.Context) {
	// Read the request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to read request body",
			"details": err.Error(),
		})
		return
	}

	// Create request to AI service
	req, err := http.NewRequest("POST", h.aiServiceURL+"/api/v1/chat/conversations", bytes.NewBuffer(body))
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

// GetConversations handles getting conversations by proxying to the AI service
func (h *AIProxyHandler) GetConversations(c *gin.Context) {
	// Create request to AI service with query parameters
	req, err := http.NewRequest("GET", h.aiServiceURL+"/api/v1/chat/conversations", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy query parameters
	req.URL.RawQuery = c.Request.URL.RawQuery

	// Copy headers
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

// GetConversation handles getting a specific conversation by proxying to the AI service
func (h *AIProxyHandler) GetConversation(c *gin.Context) {
	conversationID := c.Param("id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "conversation ID is required",
		})
		return
	}

	// Create request to AI service
	req, err := http.NewRequest("GET", h.aiServiceURL+"/api/v1/chat/conversations/"+conversationID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy headers
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

// UpdateConversation handles updating a conversation by proxying to the AI service
func (h *AIProxyHandler) UpdateConversation(c *gin.Context) {
	conversationID := c.Param("id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "conversation ID is required",
		})
		return
	}

	// Read the request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to read request body",
			"details": err.Error(),
		})
		return
	}

	// Create request to AI service
	req, err := http.NewRequest("PUT", h.aiServiceURL+"/api/v1/chat/conversations/"+conversationID, bytes.NewBuffer(body))
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

// DeleteConversation handles deleting a conversation by proxying to the AI service
func (h *AIProxyHandler) DeleteConversation(c *gin.Context) {
	conversationID := c.Param("id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "conversation ID is required",
		})
		return
	}

	// Create request to AI service
	req, err := http.NewRequest("DELETE", h.aiServiceURL+"/api/v1/chat/conversations/"+conversationID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy headers
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

// GetConversationMessages handles getting conversation messages by proxying to the AI service
func (h *AIProxyHandler) GetConversationMessages(c *gin.Context) {
	conversationID := c.Param("id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "conversation ID is required",
		})
		return
	}

	// Create request to AI service with query parameters
	req, err := http.NewRequest("GET", h.aiServiceURL+"/api/v1/chat/conversations/"+conversationID+"/messages", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy query parameters
	req.URL.RawQuery = c.Request.URL.RawQuery

	// Copy headers
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

// GetLLMProviders handles getting all LLM providers by proxying to the AI service
func (h *AIProxyHandler) GetLLMProviders(c *gin.Context) {
	h.proxyRequest(c, "GET", "/api/llm-settings/providers", nil)
}

// GetLLMProvidersStatus handles getting LLM providers status by proxying to the AI service
func (h *AIProxyHandler) GetLLMProvidersStatus(c *gin.Context) {
	h.proxyRequest(c, "GET", "/api/llm-settings/providers/status", nil)
}

// CreateLLMProvider handles creating a new LLM provider by proxying to the AI service
func (h *AIProxyHandler) CreateLLMProvider(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to read request body",
			"details": err.Error(),
		})
		return
	}
	h.proxyRequest(c, "POST", "/api/llm-settings/providers", body)
}

// UpdateLLMProvider handles updating an LLM provider by proxying to the AI service
func (h *AIProxyHandler) UpdateLLMProvider(c *gin.Context) {
	providerID := c.Param("id")
	if providerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "provider ID is required",
		})
		return
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to read request body",
			"details": err.Error(),
		})
		return
	}
	h.proxyRequest(c, "PUT", "/api/llm-settings/providers/"+providerID, body)
}

// DeleteLLMProvider handles deleting an LLM provider by proxying to the AI service
func (h *AIProxyHandler) DeleteLLMProvider(c *gin.Context) {
	providerID := c.Param("id")
	if providerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "provider ID is required",
		})
		return
	}
	h.proxyRequest(c, "DELETE", "/api/llm-settings/providers/"+providerID, nil)
}

// TestLLMProvider handles testing an LLM provider by proxying to the AI service
func (h *AIProxyHandler) TestLLMProvider(c *gin.Context) {
	providerID := c.Param("id")
	if providerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "provider ID is required",
		})
		return
	}
	h.proxyRequest(c, "POST", "/api/llm-settings/providers/"+providerID+"/test", nil)
}

// proxyRequest is a helper function to proxy requests to the AI service
func (h *AIProxyHandler) proxyRequest(c *gin.Context, method, path string, body []byte) {
	// Create request to AI service
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, h.aiServiceURL+path, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, h.aiServiceURL+path, nil)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create request to AI service",
			"details": err.Error(),
		})
		return
	}

	// Copy query parameters
	req.URL.RawQuery = c.Request.URL.RawQuery

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
